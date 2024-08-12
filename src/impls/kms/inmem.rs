use std::str::FromStr;

use async_trait::async_trait;

use crate::core_::{crypto, kms};
use crate::core_::crypto::Suite;
use crate::core_::kms::Kms;
use crate::core_::storage::Storage;
use crate::impls::crypto::suites::ed25519::Ed25519;
use crate::impls::crypto::suites::p256::P256;
use crate::impls::storage::inmem::InMemStorage;

#[derive(Clone)]
pub enum KeyHandle {
    Ed25519(Ed25519),
    P256(P256),
}

impl KeyHandle {}

#[async_trait]
impl crypto::Signer for KeyHandle {
    fn alg(&self) -> crypto::Alg {
        match self {
            KeyHandle::Ed25519(s) => s.alg(),
            KeyHandle::P256(s) => s.alg(),
        }
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.sign(payload).await,
            KeyHandle::P256(s) => s.sign(payload).await
        }
    }
}

#[async_trait]
impl crypto::Verifier for KeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.verify(data, signature).await,
            KeyHandle::P256(s) => s.verify(data, signature).await,
        }
    }
}

#[async_trait]
impl crypto::Key for KeyHandle {
    fn pub_key(&self) -> Result<Vec<u8>, crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.pub_key(),
            KeyHandle::P256(s) => s.pub_key(),
        }
    }

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

#[derive(Clone)]
pub struct LocalKms {
    storage: InMemStorage<kms::KeyID, Bytes>,
}

const KID_LENGTH: usize = 10;

impl LocalKms {
    pub fn new() -> Self {
        Self { storage: InMemStorage::new() }
    }

    pub fn for_store(storage: InMemStorage<kms::KeyID, Bytes>) -> Self {
        Self { storage }
    }

    fn kid(kt: kms::KeyType) -> kms::KeyID {
        let id = random_string::generate(KID_LENGTH, random_string::charsets::ALPHA);
        format!("{}:{}", id, kt)
    }

    fn key_type(kid: &String) -> kms::KeyType {
        let postfix = &kid[KID_LENGTH + 1..];

        kms::KeyType::from_str(postfix).unwrap()
    }
}

#[async_trait]
impl Kms<KeyHandle> for LocalKms
{
    async fn create(&mut self, kt: kms::KeyType, opts: kms::CreateOptions) -> Result<kms::KeyID, kms::Error> {
        let key = match kt {
            kms::KeyType::Ed25519 => Ed25519::gen(),
            kms::KeyType::P256 => P256::gen(),
        };

        let kid = LocalKms::kid(kt);

        let _ = self.storage.put(kid.to_owned(), key).await;

        Ok(kid.to_owned())
    }

    async fn get(&self, kid: &kms::KeyID) -> Result<KeyHandle, kms::Error> {
        let key = self.storage.get(kid).await.unwrap();

        let kt = LocalKms::key_type(kid);

        let res = match kt {
            kms::KeyType::Ed25519 => {
                Ed25519::from_secret(key.clone())
                    .map(|s| KeyHandle::Ed25519(s))
                    .map_err(|e| kms::Error::Crypto(e.to_string()))
            }
            kms::KeyType::P256 => {
                P256::from_secret(key.clone())
                    .map(|s| KeyHandle::P256(s))
                    .map_err(|e| kms::Error::Crypto(e.to_string()))
            }
        };

        res
    }
}

#[cfg(test)]
mod tests {
    use crate::core_::kms::test_util::test_kms;
    use crate::impls::kms::inmem::LocalKms;

    #[tokio::test]
    async fn e2e() {
        test_kms(LocalKms::new()).await;
    }
}