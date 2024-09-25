use crate::crypto::Suite;
use crate::inmem::crypto::ed25519::Ed25519;
use crate::inmem::crypto::p256::P256;
use crate::inmem::storage::InMemStorage;
use crate::kms::{CryptoSnafu, KeyID, Kms};
use crate::kms::{Error, NotFoundSnafu, ResolvingSnafu};
use crate::storage::Storage;
use crate::{crypto, kms};
use async_trait::async_trait;
use snafu::ResultExt;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{instrument, Level};

#[derive(Clone)]
pub enum KeyHandle {
    Ed25519(Ed25519),
    P256(P256),
}

impl KeyHandle {}

#[async_trait]
impl crypto::Signer for KeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn alg(&self) -> crypto::Alg {
        match self {
            KeyHandle::Ed25519(s) => s.alg(),
            KeyHandle::P256(s) => s.alg(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.sign(payload).await,
            KeyHandle::P256(s) => s.sign(payload).await,
        }
    }
}

#[async_trait]
impl crypto::Verifier for KeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.verify(data, signature).await,
            KeyHandle::P256(s) => s.verify(data, signature).await,
        }
    }
}

#[async_trait]
impl crypto::Key for KeyHandle {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    fn pub_key(&self) -> Result<Vec<u8>, crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.pub_key(),
            KeyHandle::P256(s) => s.pub_key(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
        ret(),
    )]
    fn jwk(&self) -> Option<ssi::jwk::JWK> {
        match self {
            KeyHandle::Ed25519(s) => s.jwk(),
            KeyHandle::P256(s) => s.jwk(),
        }
    }
}

#[async_trait]
impl crypto::SigningKey for KeyHandle {}

#[async_trait]
impl crypto::VerifyingKey for KeyHandle {}

#[async_trait]
impl kms::KeyHandle for KeyHandle {}

pub type Bytes = Vec<u8>;

#[derive(Debug, Clone)]
pub struct LocalKms {
    storage: Arc<InMemStorage<KeyID, Bytes>>,
}

const KID_LENGTH: usize = 10;

impl LocalKms {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(InMemStorage::new()),
        }
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn for_store(storage: InMemStorage<kms::KeyID, Bytes>) -> Self {
        Self {
            storage: Arc::new(storage),
        }
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn kid(kt: kms::KeyType) -> kms::KeyID {
        let id = random_string::generate(KID_LENGTH, random_string::charsets::ALPHA);
        format!("{}:{}", id, kt)
    }

    fn key_type(kid: &str) -> kms::KeyType {
        let postfix = &kid[KID_LENGTH + 1..];

        kms::KeyType::from_str(postfix).unwrap()
    }
}

#[async_trait]
impl Kms<KeyHandle> for LocalKms {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn create(&self, kt: kms::KeyType, opts: kms::CreateOptions) -> Result<KeyID, Error> {
        let key = match kt {
            kms::KeyType::Ed25519 => Ed25519::gen(),
            kms::KeyType::P256 => P256::gen(),
        };

        let kid = LocalKms::kid(kt);

        let _ = self.storage.put(kid.to_owned(), key).await;

        Ok(kid.to_owned())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
    )]
    async fn get(&self, kid: &KeyID) -> Result<KeyHandle, Error> {
        let key = self
            .storage
            .get(kid)
            .await
            .map_err(|e| {
                ResolvingSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .ok_or(NotFoundSnafu { id: kid }.build())?;

        let kt = LocalKms::key_type(kid);

        let res = match kt {
            kms::KeyType::Ed25519 => Ed25519::from_secret(key.clone())
                .map(KeyHandle::Ed25519)
                .context(CryptoSnafu)?,
            kms::KeyType::P256 => P256::from_secret(key.clone())
                .map(KeyHandle::P256)
                .context(CryptoSnafu)?,
        };

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::inmem::kms::LocalKms;
    use crate::kms::test_util::test_kms;

    #[tokio::test]
    async fn e2e() {
        test_kms(LocalKms::new()).await;
    }
}
