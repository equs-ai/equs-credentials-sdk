use aries_askar::crypto::alg::EcCurves;
use aries_askar::kms::{KeyAlg, LocalKey};
use aries_askar::Store;
use async_trait::async_trait;
use snafu::{ensure, ResultExt};
use std::sync::Arc;
use tracing::{instrument, Level};

use agent_sdk::crypto::{
    Alg, AlgNotSupportedSnafu, Error as CryptoError, Key, KeyNotSupportedSnafu, Signer, SigningKey,
    SigningSnafu, VerificationSnafu, Verifier, VerifyingKey, JWK,
};
use agent_sdk::kms::{
    CreateOptions, CreationSnafu, CryptoSnafu, Error as KmsError, KeyHandle, KeyID, KeyType, Kms,
    NotFoundSnafu, ResolvingSnafu,
};

#[derive(Debug, Clone)]
pub struct AskarKeyHandle(Arc<LocalKey>, Alg);

impl AskarKeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn askar_sign_type(&self) -> Result<&'static str, CryptoError> {
        match self.alg() {
            Alg::ES256 => Ok("es256"),
            Alg::EdDSA => Ok("eddsa"),
            _ => AlgNotSupportedSnafu {
                alg: format!("{}", self.alg()),
            }
            .fail(),
        }
    }
}

impl SigningKey for AskarKeyHandle {}

impl Key for AskarKeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    fn pub_key(&self) -> Result<Vec<u8>, CryptoError> {
        self.0
            .to_public_bytes()
            .map_err(|_| KeyNotSupportedSnafu { type_: "public" }.build())
            .map(|public_key| public_key.to_vec())
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn jwk(&self) -> Option<JWK> {
        let jwk = self.0.to_jwk_public(None).ok()?;
        serde_json::from_str::<JWK>(&jwk).ok()
    }
}

#[async_trait]
impl Signer for AskarKeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn alg(&self) -> Alg {
        self.1
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sign_type = self.askar_sign_type()?;

        self.0
            .sign_message(payload, Some(sign_type))
            .map_err(|err| {
                SigningSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }
}

impl VerifyingKey for AskarKeyHandle {}

#[async_trait]
impl Verifier for AskarKeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sign_type = self.askar_sign_type()?;
        let valid = self
            .0
            .verify_signature(data, signature, Some(sign_type))
            .map_err(|err| {
                VerificationSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        ensure!(
            valid,
            VerificationSnafu {
                details: "Signature is not valid"
            }
        );

        Ok(())
    }
}

impl KeyHandle for AskarKeyHandle {}

const KID_LENGTH: usize = 10;

#[derive(Debug)]
pub struct AskarKms(Store);

impl AskarKms {
    #[instrument(
        level = Level::TRACE,
        skip_all
    )]
    pub(super) fn new(store: Store) -> Self {
        AskarKms(store)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn insert_key(&self, key_id: &str, key: &LocalKey) -> Result<(), aries_askar::Error> {
        let mut session = self.0.session(None).await?;
        session
            .insert_key(key_id, key, None, None, None, None)
            .await?;
        session.commit().await?;

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn get_key(&self, key_id: &str) -> Result<Option<LocalKey>, aries_askar::Error> {
        let mut session = self.0.session(None).await?;

        session
            .fetch_key(key_id, false)
            .await?
            .map(|key_entry| key_entry.load_local_key())
            .transpose()
    }
}

#[async_trait]
impl Kms<AskarKeyHandle> for AskarKms {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn create(&self, kt: KeyType, _opts: CreateOptions) -> Result<KeyID, KmsError> {
        let key_alg = key_type_to_key_alg(kt).context(CryptoSnafu)?;
        let key = LocalKey::generate_with_rng(key_alg, false).map_err(|e| {
            CreationSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        let kid = random_string::generate(KID_LENGTH, random_string::charsets::ALPHA);
        self.insert_key(&kid, &key).await.map_err(|e| {
            CreationSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        Ok(kid)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn get(&self, kid: &KeyID) -> Result<AskarKeyHandle, KmsError> {
        let key = self
            .get_key(kid)
            .await
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?
            .ok_or_else(|| NotFoundSnafu { id: kid }.build())?;

        let sign_algorithm = key_alg_to_alg(key.algorithm()).context(CryptoSnafu)?;

        Ok(AskarKeyHandle(Arc::new(key), sign_algorithm))
    }
}

fn key_alg_to_alg(key_alg: KeyAlg) -> Result<Alg, CryptoError> {
    match key_alg {
        KeyAlg::Ed25519 => Ok(Alg::EdDSA),
        KeyAlg::EcCurve(EcCurves::Secp256r1) => Ok(Alg::ES256),
        _ => AlgNotSupportedSnafu {
            alg: key_alg.as_str(),
        }
        .fail(),
    }
}

fn key_type_to_key_alg(key_type: KeyType) -> Result<KeyAlg, CryptoError> {
    match key_type {
        KeyType::P256 => Ok(KeyAlg::EcCurve(EcCurves::Secp256r1)),
        KeyType::Ed25519 => Ok(KeyAlg::Ed25519),
        _ => KeyNotSupportedSnafu {
            type_: format!("{}", key_type),
        }
        .fail(),
    }
}

#[cfg(test)]
mod tests {
    use crate::AskarStorage;
    use agent_sdk::kms;
    use agent_sdk::kms::{KeyHandle, Kms};

    // TODO: consider splitting this test into several small unit tests
    #[tokio::test]
    async fn test_askar_kms() {
        let storage = AskarStorage::create("sEcrEt", Some("Askar-Wallet".to_string()))
            .await
            .unwrap();
        let kms = storage.kms();
        test_kms(kms).await;
        storage.close().await.unwrap();
    }

    pub async fn test_kms<KH: KeyHandle, KMS: Kms<KH>>(kms: KMS) {
        for kt in [kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Create a key
            let create_res = kms.create(kt.clone(), kms::CreateOptions {}).await;
            assert!(create_res.is_ok());
            let kid = create_res.unwrap();

            // Get a handle to the key
            let get_res = kms.get(&kid).await;
            assert!(get_res.is_ok());
            let kh = get_res.unwrap();

            // Sign using handle
            let message = "abracadabra";

            let s_res = kh.sign(message.as_bytes()).await;
            assert!(s_res.is_ok());

            let signature = s_res.unwrap();

            // Verify using handle
            let v_res = kh.verify(message.as_bytes(), &signature).await;
            assert!(v_res.is_ok());

            // Check JWK
            assert_ne!(kh.jwk(), None);

            // Print jwks
            let jwk = kh.jwk().unwrap();
            println!("JWK: {}", serde_json::to_string_pretty(&jwk).unwrap())
        }
    }
}
