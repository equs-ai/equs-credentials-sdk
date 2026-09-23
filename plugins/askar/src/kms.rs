use aries_askar::Session;
use aries_askar::crypto::alg::EcCurves;
use aries_askar::crypto::generic_array::ArrayLength;
use aries_askar::entry::{EntryTag, TagFilter};
use aries_askar::kms::{KeyAlg, LocalKey};
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bip32::secp256k1::elliptic_curve::ops::Invert;
use bip32::secp256k1::elliptic_curve::point::PointCompression;
use bip32::secp256k1::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use bip32::secp256k1::elliptic_curve::subtle::CtOption;
use bip32::secp256k1::elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, PrimeCurve, Scalar, sec1,
};
use ecdsa::SignatureSize;
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use rand::Rng;
use rand::distr::Alphanumeric;
use sha2::{Digest, Sha256};
use snafu::{ResultExt, ensure};
use std::sync::Arc;
use tracing::{Level, instrument};

use aries_askar::crypto::kdf::KeyExchange;

use equs_sdk::crypto::{
    AlgNotSupportedSnafu, Error as CryptoError, IncorrectKeySnafu, JWK, KeyNotSupportedSnafu,
    SigningSnafu, VerificationSnafu,
};
use equs_sdk::kms::{
    CreateOptions, CreationSnafu, CryptoSnafu, Error as KmsError, Error, KeyHandle, KeyID,
    NotFoundSnafu, ResolvingSnafu,
};

use crate::AskarStorage;
pub use equs_sdk::crypto::{Alg, Key, Signer, SigningKey, Verifier, VerifyingKey};
pub use equs_sdk::kms::{JweDecryptBytes, KeyAgreement, KeyType, Kms};

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
            Alg::ES256K => Ok("es256k"),
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

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn private_key(&self) -> Result<Vec<u8>, CryptoError> {
        self.0
            .to_secret_bytes()
            .map_err(|_| KeyNotSupportedSnafu { type_: "private" }.build())
            .map(|secret_bytes| secret_bytes.to_vec())
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
const PUBLIC_KEY_TAG_NAME: &str = "public_key";

#[derive(Clone, Debug)]
pub struct AskarKms {
    storage: AskarStorage,
    profile: String,
}

impl AskarKms {
    async fn session(&self) -> Result<Session, aries_askar::Error> {
        self.storage.session(Some(self.profile.clone())).await
    }
}

impl AskarKms {
    #[instrument(
        level = Level::TRACE,
        skip_all
    )]
    pub fn new(storage: &AskarStorage, profile: String) -> Self {
        AskarKms {
            storage: storage.to_owned(),
            profile,
        }
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
        let mut session = self.session().await?;
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
        let mut session = self.session().await?;

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
        let mut session = self.session().await?;

        let public_key_filter =
            TagFilter::is_eq(PUBLIC_KEY_TAG_NAME, Self::public_key_to_id(public_key));

        session
            .fetch_all_keys(None, None, Some(public_key_filter), None, None, false)
            .await?
            .first()
            .map(|key_entry| key_entry.load_local_key())
            .transpose()
    }

    pub async fn create_public_key_tags(key: &LocalKey) -> Result<Vec<EntryTag>, Error> {
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
            PUBLIC_KEY_TAG_NAME.to_string(),
            public_key_id.to_owned(),
        ));

        let re_encoded_key = match key.algorithm() {
            KeyAlg::EcCurve(EcCurves::Secp256r1) => {
                Some(Self::re_encode_public_key::<p256::NistP256>(
                    &public_key,
                    !Self::is_compressed_public_key::<p256::NistP256>(&public_key)?,
                )?)
            }
            KeyAlg::EcCurve(EcCurves::Secp256k1) => {
                Some(Self::re_encode_public_key::<bip32::secp256k1::Secp256k1>(
                    &public_key,
                    !Self::is_compressed_public_key::<bip32::secp256k1::Secp256k1>(&public_key)?,
                )?)
            }
            _ => None,
        };

        if let Some(re_encoded_key) = re_encoded_key {
            let re_encoded_pk_id = Self::public_key_to_id(&re_encoded_key);
            tags.push(EntryTag::Encrypted(
                PUBLIC_KEY_TAG_NAME.to_string(),
                re_encoded_pk_id,
            ));
        }

        Ok(tags)
    }

    fn public_key_to_id(public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize().to_vec();

        BASE64_STANDARD.encode(&hash)
    }

    pub fn re_encode_public_key<C>(public_key: &[u8], compress: bool) -> Result<Vec<u8>, Error>
    where
        C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
        SignatureSize<C>: ArrayLength<u8>,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
    {
        let encoded_point = ecdsa::EncodedPoint::<C>::from_bytes(public_key).map_err(|err| {
            CreationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let verifying_key =
            ecdsa::VerifyingKey::<C>::from_encoded_point(&encoded_point).map_err(|err| {
                CreationSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        Ok(verifying_key.to_encoded_point(compress).as_bytes().to_vec())
    }

    pub fn is_compressed_public_key<C>(public_key: &[u8]) -> Result<bool, Error>
    where
        C: PrimeCurve + CurveArithmetic + PointCompression + DigestPrimitive,
        Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
        SignatureSize<C>: ArrayLength<u8>,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
    {
        ecdsa::EncodedPoint::<C>::from_bytes(public_key)
            .map(|encoded_point| encoded_point.is_compressed())
            .map_err(|err| {
                CreationSnafu {
                    details: err.to_string(),
                }
                .build()
            })
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

        let kid = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(KID_LENGTH)
            .map(char::from)
            .collect::<String>();
        let tags = Self::create_public_key_tags(&key).await?;

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
        KeyAlg::EcCurve(EcCurves::Secp256k1) => Ok(Alg::ES256K),
        _ => AlgNotSupportedSnafu {
            alg: key_alg.as_str(),
        }
        .fail(),
    }
}

fn key_type_to_key_alg(key_type: KeyType) -> Result<KeyAlg, CryptoError> {
    match key_type {
        KeyType::P256 => Ok(KeyAlg::EcCurve(EcCurves::Secp256r1)),
        KeyType::K256 => Ok(KeyAlg::EcCurve(EcCurves::Secp256k1)),
        KeyType::Ed25519 => Ok(KeyAlg::Ed25519),
        _ => KeyNotSupportedSnafu {
            type_: format!("{}", key_type),
        }
        .fail(),
    }
}

#[async_trait]
impl KeyAgreement for AskarKeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
    )]
    async fn shared_secret(&self, remote_jwk: &str) -> Result<Vec<u8>, CryptoError> {
        // The remote (ephemeral) public key travels in the JWE header.
        let ephem = LocalKey::from_jwk(remote_jwk).map_err(|e| {
            IncorrectKeySnafu {
                details: format!("Failed to parse remote JWK: {e}"),
            }
            .build()
        })?;

        let secret = match self.alg() {
            Alg::ES256 => self.0.key_exchange_bytes(&ephem).map_err(|e| {
                IncorrectKeySnafu {
                    details: format!("Key agreement failed: {e}"),
                }
                .build()
            })?,
            Alg::EdDSA => {
                let x25519 = self.0.convert_key(KeyAlg::X25519).map_err(|e| {
                    IncorrectKeySnafu {
                        details: format!("Failed to convert key to X25519: {e}"),
                    }
                    .build()
                })?;
                x25519.key_exchange_bytes(&ephem).map_err(|e| {
                    IncorrectKeySnafu {
                        details: format!("Key agreement failed: {e}"),
                    }
                    .build()
                })?
            }
            other => {
                return AlgNotSupportedSnafu {
                    alg: other.to_string(),
                }
                .fail();
            }
        };

        Ok(secret.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::kms::AskarKms;
    use crate::{AskarStorage, AskarStorageConfig, KeyMethod};
    use equs_sdk::kms;
    use equs_sdk::kms::{KeyHandle, Kms};
    use equs_sdk::vc::oid4vp::jwe::test_utils;

    // TODO: consider splitting this test into several small unit tests
    #[tokio::test]
    async fn test_askar_kms() {
        let kms = askar_kms().await;
        test_kms(&kms).await;
    }

    pub async fn test_kms<KH: KeyHandle, KMS: Kms<KH>>(kms: &KMS) {
        for kt in [
            kms::KeyType::Ed25519,
            kms::KeyType::P256,
            kms::KeyType::K256,
        ] {
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

    #[tokio::test]
    async fn jwe_encrypt_decrypt() {
        let kms = askar_kms().await;
        test_utils::test_kms_encrypt_decrypt(kms).await;
    }

    #[tokio::test]
    async fn shared_secret_is_symmetric_for_p256() {
        use equs_sdk::crypto::Key;
        use equs_sdk::kms::KeyAgreement;

        let kms = askar_kms().await;
        let alice = kms
            .create(kms::KeyType::P256, kms::CreateOptions::default())
            .await
            .unwrap();
        let bob = kms
            .create(kms::KeyType::P256, kms::CreateOptions::default())
            .await
            .unwrap();
        let alice_kh = kms.get(&alice).await.unwrap();
        let bob_kh = kms.get(&bob).await.unwrap();

        let alice_jwk = serde_json::to_string(&alice_kh.jwk().unwrap()).unwrap();
        let bob_jwk = serde_json::to_string(&bob_kh.jwk().unwrap()).unwrap();

        // ECDH is symmetric: Alice·Bob_pub == Bob·Alice_pub. The private keys
        // never leave the vault — only the derived secret is returned.
        let ab = alice_kh.shared_secret(&bob_jwk).await.unwrap();
        let ba = bob_kh.shared_secret(&alice_jwk).await.unwrap();

        assert_eq!(ab, ba);
        assert_eq!(
            ab.len(),
            32,
            "P-256 shared secret is the 32-byte x-coordinate"
        );
    }

    #[tokio::test]
    async fn shared_secret_rejects_unsupported_key_type() {
        use equs_sdk::crypto::{Error as CryptoError, Key};
        use equs_sdk::kms::KeyAgreement;

        let kms = askar_kms().await;
        // K256 (ES256K) is a signing curve without ECDH-ES support here.
        let signer = kms
            .create(kms::KeyType::K256, kms::CreateOptions::default())
            .await
            .unwrap();
        let signer_kh = kms.get(&signer).await.unwrap();

        // A well-formed remote key so parsing succeeds and we reach the alg check.
        let peer = kms
            .create(kms::KeyType::P256, kms::CreateOptions::default())
            .await
            .unwrap();
        let peer_jwk =
            serde_json::to_string(&kms.get(&peer).await.unwrap().jwk().unwrap()).unwrap();

        let err = signer_kh.shared_secret(&peer_jwk).await.unwrap_err();
        assert!(matches!(err, CryptoError::AlgNotSupported { .. }));
    }

    #[tokio::test]
    async fn shared_secret_rejects_malformed_remote_jwk() {
        use equs_sdk::crypto::Error as CryptoError;
        use equs_sdk::kms::KeyAgreement;

        let kms = askar_kms().await;
        let kid = kms
            .create(kms::KeyType::P256, kms::CreateOptions::default())
            .await
            .unwrap();
        let kh = kms.get(&kid).await.unwrap();

        let err = kh.shared_secret("not-a-valid-jwk").await.unwrap_err();
        assert!(matches!(err, CryptoError::IncorrectKey { .. }));
    }

    async fn askar_kms() -> AskarKms {
        let storage = AskarStorage::create(
            &AskarStorageConfig {
                db_url: "sqlite://:memory:".to_owned(),
                key_method: KeyMethod::DeriveKey,
                pass_key: "1234".to_string(),
                profile: "test".to_string(),
            },
            false,
        )
        .await
        .unwrap();

        let profile = "test_profile".to_string();

        storage.ensure_profile(profile.clone()).await.unwrap();
        AskarKms::new(&storage, profile)
    }
}
