use async_trait::async_trait;
use strum_macros::{Display, EnumString, IntoStaticStr};

use crate::core_::crypto;

// Error handling
#[derive(Debug, thiserror::Error, IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(String),
}

// Basic types definitions

pub type KeyID = String;

#[derive(Debug, PartialEq)]
#[derive(Display, EnumString, IntoStaticStr)]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    P256,
    // etc
}

// Method options
#[derive(Default)]
pub struct CreateOptions {}

pub trait KeyHandle: crypto::SigningKey + crypto::VerifyingKey + crypto::Key + Clone {}

#[async_trait]
pub trait Kms<KH>: Send + Sync
where
    KH: KeyHandle,
{
    async fn create(&mut self, kt: &KeyType, opts: CreateOptions) -> Result<KeyID, Error>;

    async fn get(&self, kid: &KeyID) -> Result<KH, Error>;

    async fn create_and_handle(&mut self, kt: &KeyType, opts: CreateOptions) -> Result<(KeyID, KH), Error> {
        let res = self.create(kt, opts).await;
        if res.is_err() { return Err(res.err().unwrap()); }
        let kid = res.unwrap();

        let res = self.get(&kid).await;
        if res.is_err() { return Err(res.err().unwrap()); }

        Ok((kid, res.unwrap()))
    }
}