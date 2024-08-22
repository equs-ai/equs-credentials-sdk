use async_trait::async_trait;
use strum_macros::{Display, EnumString, IntoStaticStr};

use crate::crypto;

// Error handling
#[derive(Debug, thiserror::Error, IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Create key error: {0}")]
    Creation(String),
    #[error("Resolving error: {0}")]
    Resolving(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::Error),
}

pub type KeyID = String;

#[derive(Debug, PartialEq, Clone)]
#[derive(Display, EnumString, IntoStaticStr)]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    P256,
    // etc
}

// Method options
#[derive(Default, PartialEq, Clone)]
pub struct CreateOptions {}

pub trait KeyHandle: crypto::SigningKey + crypto::VerifyingKey + crypto::Key + Clone {}

#[async_trait]
pub trait Kms<KH>: Send + Sync
where
    KH: KeyHandle,
{
    async fn create(&self, kt: KeyType, opts: CreateOptions) -> Result<KeyID, Error>;

    async fn get(&self, kid: &KeyID) -> Result<KH, Error>;

    async fn create_and_handle(&self, kt: KeyType, opts: CreateOptions) -> Result<(KeyID, KH), Error> {
        let kid = self.create(kt, opts).await?;
        let res = self.get(&kid).await?;

        Ok((kid, res))
    }
}

#[cfg(test)]
pub mod test_util {
    use crate::kms;
    use crate::kms::{KeyHandle, Kms};

    pub async fn test_kms<KH: KeyHandle, KMS: Kms<KH>>(kms: KMS) {
        for kt in vec![kms::KeyType::Ed25519, kms::KeyType::P256] {
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