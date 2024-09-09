use aries_askar::crypto::alg::EcCurves;
use aries_askar::kms::{KeyAlg, LocalKey};
use aries_askar::Store;
use async_trait::async_trait;
use snafu::{ensure, ResultExt};
use ssi::jwk::JWK;
use std::sync::Arc;
use tracing::{instrument, Level};

use crate::crypto::{
    Alg, AlgNotSupportedSnafu, Error as CryptoError, Key, KeyNotSupportedSnafu, Signer, SigningKey,
    SigningSnafu, VerificationSnafu, Verifier, VerifyingKey,
};
use crate::kms::{
    CreateOptions, CreationSnafu, CryptoSnafu, Error as KmsError, KeyHandle, KeyID, KeyType, Kms,
    NotFoundSnafu, ResolvingSnafu,
};

#[derive(Debug, Clone)]
pub struct AskarKeyHandle(Arc<LocalKey>, Alg);

impl AskarKeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(level = Level::TRACE)
    )]
    fn askar_sign_type(&self) -> &'static str {
        match self.alg() {
            Alg::ES256 => "es256",
            Alg::EdDSA => "eddsa",
        }
    }
}

impl SigningKey for AskarKeyHandle {}

impl Key for AskarKeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE)
    )]
    fn pub_key(&self) -> Result<Vec<u8>, CryptoError> {
        self.0
            .to_public_bytes()
            .map_err(|err| KeyNotSupportedSnafu { type_: "public" }.build())
            .map(|public_key| public_key.to_vec())
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
    )]
    fn alg(&self) -> Alg {
        self.1
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0
            .sign_message(payload, Some(self.askar_sign_type()))
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
        ret(level = Level::TRACE)
    )]
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let valid = self
            .0
            .verify_signature(data, signature, Some(self.askar_sign_type()))
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
        ret(level = Level::TRACE)
    )]
    async fn insert_key(&self, key_id: &str, key: &LocalKey) -> Result<(), aries_askar::Error> {
        let mut session = self.0.session(None).await?;
        session.insert_key(key_id, key, None, None, None).await?;
        session.commit().await?;

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
    )]
    async fn create(&self, kt: KeyType, opts: CreateOptions) -> Result<KeyID, KmsError> {
        let key = LocalKey::generate(kt.into(), false).map_err(|e| {
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
        ret(level = Level::TRACE)
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

        let sign_algorithm = key.algorithm().try_into().context(CryptoSnafu)?;

        Ok(AskarKeyHandle(Arc::new(key), sign_algorithm))
    }
}

impl TryFrom<KeyAlg> for Alg {
    type Error = CryptoError;

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE)
    )]
    fn try_from(value: KeyAlg) -> Result<Self, Self::Error> {
        match value {
            KeyAlg::Ed25519 => Ok(Alg::EdDSA),
            KeyAlg::EcCurve(EcCurves::Secp256r1) => Ok(Alg::ES256),
            _ => AlgNotSupportedSnafu {
                alg: value.as_str(),
            }
            .fail(),
        }
    }
}

impl From<KeyType> for KeyAlg {
    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE)
    )]
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::P256 => KeyAlg::EcCurve(EcCurves::Secp256r1),
            KeyType::Ed25519 => KeyAlg::Ed25519,
        }
    }
}
