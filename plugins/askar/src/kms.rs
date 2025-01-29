use aries_askar::crypto::alg::EcCurves;
use aries_askar::entry::{EntryTag, TagFilter};
use aries_askar::kms::{KeyAlg, LocalKey};
use aries_askar::Store;
use async_trait::async_trait;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use snafu::{ensure, ResultExt};
use std::sync::Arc;
use tracing::{instrument, Level};

use agent_sdk::crypto::{
    Alg, AlgNotSupportedSnafu, Error as CryptoError, Key, KeyNotSupportedSnafu, Signer, SigningKey,
    SigningSnafu, VerificationSnafu, Verifier, VerifyingKey, JWK,
};
use agent_sdk::inmem::crypto::k256::K256;
use agent_sdk::inmem::crypto::p256::P256;
use agent_sdk::kms::{
    CreateOptions, CreationSnafu, CryptoSnafu, Error as KmsError, Error, KeyHandle, KeyID, KeyType,
    Kms, NotFoundSnafu, ResolvingSnafu,
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

const KID_LENGTH: usize = 16;

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
    async fn insert_key(
        &self,
        key_id: &str,
        key: &LocalKey,
        tags: Option<&[EntryTag]>,
    ) -> Result<(), aries_askar::Error> {
        let mut session = self.0.session(None).await?;
        session
            .insert_key(key_id, key, None, None, tags, None)
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

    async fn get_key_by_public_key(
        &self,
        public_key: &[u8],
    ) -> Result<Option<LocalKey>, aries_askar::Error> {
        let mut session = self.0.session(None).await?;

        let public_key_filter = TagFilter::exist(vec![Self::public_key_to_id(public_key)]);

        session
            .fetch_all_keys(None, None, Some(public_key_filter), None, false)
            .await?
            .first()
            .map(|key_entry| key_entry.load_local_key())
            .transpose()
    }

    pub async fn map_kid_to_public_key(kid: &str, key: &LocalKey) -> Result<Vec<EntryTag>, Error> {
        let mut tags: Vec<EntryTag> = vec![];

        let public_key = key
            .to_public_bytes()
            .map_err(|e| {
                CreationSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .to_vec();

        let public_key_id = Self::public_key_to_id(&public_key);
        tags.push(EntryTag::Encrypted(
            public_key_id.to_owned(),
            kid.to_string(),
        ));

        let re_encoded_key = match key.algorithm() {
            KeyAlg::EcCurve(EcCurves::Secp256k1) => Some(K256::re_encode_public_key(
                &public_key,
                !K256::is_compressed_public_key(&public_key)?,
            )?),
            KeyAlg::EcCurve(EcCurves::Secp256r1) => Some(P256::re_encode_public_key(
                &public_key,
                !P256::is_compressed_public_key(&public_key)?,
            )?),
            _ => None,
        };

        if let Some(re_encoded_key) = re_encoded_key {
            let re_encoded_pk_id = Self::public_key_to_id(&re_encoded_key);
            tags.push(EntryTag::Encrypted(re_encoded_pk_id, kid.to_string()));
        }

        Ok(tags)
    }

    fn public_key_to_id(public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize().to_vec();

        BASE64_STANDARD.encode(&hash[..16])
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
        let tags = Self::map_kid_to_public_key(&kid, &key).await?;

        self.insert_key(&kid, &key, Some(&tags))
            .await
            .map_err(|e| {
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

    async fn get_by_public_key(&self, public_key: &[u8]) -> Result<AskarKeyHandle, KmsError> {
        let key = self
            .get_key_by_public_key(public_key)
            .await
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?
            .ok_or_else(|| NotFoundSnafu { id: "Public Key" }.build())?;

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
            let kid = kms
                .create(kt.clone(), kms::CreateOptions::default())
                .await
                .unwrap();

            // Get a handle to the key
            let kh = kms.get(&kid).await.unwrap();

            // Get a handle to the key by Public Key
            kms.get_by_public_key(&kh.pub_key().unwrap()).await.unwrap();

            // Sign using handle
            let message = "abracadabra";

            let signature = kh.sign(message.as_bytes()).await.unwrap();

            // Verify using handle
            kh.verify(message.as_bytes(), &signature).await.unwrap();

            // Check JWK
            assert_ne!(kh.jwk(), None);

            // Print jwks
            let jwk = kh.jwk().unwrap();
            println!("JWK: {}", serde_json::to_string_pretty(&jwk).unwrap())
        }
    }
}
