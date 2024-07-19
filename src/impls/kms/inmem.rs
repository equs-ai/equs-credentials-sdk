use std::str::FromStr;

use crate::core_::{crypto, kms};
use crate::core_::crypto::{Key, Suite};
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

impl crypto::Signer for KeyHandle {
    fn alg(&self) -> crypto::Alg {
        match self {
            KeyHandle::Ed25519(s) => crypto::Alg::ED25519,
            KeyHandle::P256(s) => crypto::Alg::ES256,
        }
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.sign(payload).await,
            KeyHandle::P256(s) => s.sign(payload).await
        }
    }
}

impl crypto::Verifier for KeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), crypto::Error> {
        match self {
            KeyHandle::Ed25519(s) => s.verify(data, signature).await,
            KeyHandle::P256(s) => s.verify(data, signature).await,
        }
    }
}

impl Key for KeyHandle {
    fn pub_key(&self) -> Vec<u8> {
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

impl kms::KeyHandle for KeyHandle {}

pub type Bytes = Vec<u8>;

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

    fn kid(kt: &kms::KeyType) -> kms::KeyID {
        let id = random_string::generate(KID_LENGTH, random_string::charsets::ALPHA);
        format!("{}:{}", id, kt)
    }

    fn key_type(kid: &String) -> kms::KeyType {
        let postfix = &kid[KID_LENGTH + 1..];

        kms::KeyType::from_str(postfix).unwrap()
    }
}

impl Kms<KeyHandle> for LocalKms
{
    async fn create(&mut self, kt: &kms::KeyType, opts: kms::CreateOptions) -> Result<kms::KeyID, kms::Error> {
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
                Ed25519::from_secret(key.clone()).map(|s| KeyHandle::Ed25519(s)).map_err(|e| kms::Error::Crypto(e))
            }
            kms::KeyType::P256 => {
                P256::from_secret(key.clone()).map(|s| KeyHandle::P256(s)).map_err(|e| kms::Error::Crypto(e))
            }
        };

        res
    }
}

#[cfg(test)]
mod tests {
    use crate::core_::crypto::{Key, Signer, Verifier};
    use crate::core_::kms;
    use crate::core_::kms::Kms;
    use crate::impls::kms::inmem::LocalKms;

    #[tokio::test]
    async fn e2e() {
        let mut kms = LocalKms::new();

        for kt in vec![kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Create a key
            let create_res = kms.create(&kt, kms::CreateOptions {}).await;
            assert!(create_res.is_ok());
            let kid = create_res.unwrap();

            // Check key type
            assert_eq!(&kid[10 + 1..], &kt.to_string());

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