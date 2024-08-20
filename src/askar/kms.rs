use std::sync::Arc;

use aries_askar::crypto::alg::EcCurves;
use aries_askar::kms::{KeyAlg, LocalKey};
use aries_askar::Store;
use async_trait::async_trait;
use ssi::jwk::JWK;

use crate::crypto::{Alg, Error, Key, Signer, SigningKey, Verifier, VerifyingKey};
use crate::kms;
use crate::kms::{CreateOptions, KeyHandle, KeyID, KeyType, Kms};

#[derive(Debug, Clone)]
pub struct AskarKeyHandle(Arc<LocalKey>, Alg);

impl AskarKeyHandle {
    fn askar_sign_type(&self) -> &'static str {
        match self.alg() {
            Alg::ES256 => "es256",
            Alg::EdDSA => "eddsa",
        }
    }
}

impl SigningKey for AskarKeyHandle {}

impl Key for AskarKeyHandle {
    fn pub_key(&self) -> Result<Vec<u8>, Error> {
        self.0
            .to_public_bytes()
            .map_err(|err| Error::KeyNotSupported(err.to_string()))
            .and_then(|public_key| Ok(public_key.to_vec()))
    }

    fn jwk(&self) -> Option<JWK> {
        let jwk = self.0.to_jwk_public(None).ok()?;
        serde_json::from_str::<JWK>(&jwk).ok()
    }
}

#[async_trait]
impl Signer for AskarKeyHandle {
    fn alg(&self) -> Alg {
        self.1
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.0
            .sign_message(payload, Some(self.askar_sign_type()))
            .map_err(|err| Error::Signature(err.to_string()))
    }
}

impl VerifyingKey for AskarKeyHandle {}

#[async_trait]
impl Verifier for AskarKeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let valid = self.0
            .verify_signature(data, signature, Some(self.askar_sign_type()))
            .map_err(|err| Error::Verification(err.to_string()))?;

        if !valid {
            return Err(Error::Verification("Signature is not valid".to_string()));
        }

        Ok(())
    }
}

impl KeyHandle for AskarKeyHandle {}

impl TryFrom<KeyAlg> for Alg {
    type Error = Error;

    fn try_from(value: KeyAlg) -> Result<Self, Self::Error> {
        match value {
            KeyAlg::Ed25519 => Ok(Alg::EdDSA),
            KeyAlg::EcCurve(EcCurves::Secp256r1) => Ok(Alg::ES256),
            _ => Err(Error::KeyNotSupported(format!("signing algorithm: {}", value.as_str()))),
        }
    }
}

impl From<KeyType> for KeyAlg {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::P256 => KeyAlg::EcCurve(EcCurves::Secp256r1),
            KeyType::Ed25519 => KeyAlg::Ed25519,
        }
    }
}

const KID_LENGTH: usize = 10;

pub struct AskarKms(Store);

impl AskarKms {
    pub(super) fn new(store: Store) -> Self {
        AskarKms(store)
    }

    async fn insert_key(&self, key_id: &str, key: &LocalKey) -> Result<(), aries_askar::Error> {
        let mut session = self.0.session(None).await?;
        session.insert_key(key_id, key, None, None, None).await?;
        session.commit().await?;

        Ok(())
    }

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
    async fn create(&mut self, kt: KeyType, opts: CreateOptions) -> Result<KeyID, kms::Error> {
        let key =
            LocalKey::generate(kt.into(), false).map_err(|e| kms::Error::Crypto(e.to_string()))?;

        let kid = random_string::generate(KID_LENGTH, random_string::charsets::ALPHA);
        self.insert_key(&kid, &key)
            .await
            .map_err(|e| kms::Error::Crypto(e.to_string()))?;

        Ok(kid)
    }

    async fn get(&self, kid: &KeyID) -> Result<AskarKeyHandle, kms::Error> {
        let key = self.get_key(kid)
            .await
            .map_err(|err| kms::Error::Crypto(err.to_string()))?
            .ok_or_else(|| kms::Error::Crypto(format!("Key is not for ID: {}", kid)))?;

        let sign_algorithm = key
            .algorithm()
            .try_into()
            .map_err(|err: Error| kms::Error::Crypto(err.to_string()))?;

        Ok(AskarKeyHandle(Arc::new(key), sign_algorithm))
    }
}
