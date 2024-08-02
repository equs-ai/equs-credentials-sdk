use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString, IntoStaticStr};

// Error handling
#[derive(Debug, thiserror::Error, IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("key not supported")]
    KeyNotSupported,
    #[error("signing error: {0}")]
    Signature(String),
    #[error("verifying error: {0}")]
    Verification(String),
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[derive(Display, EnumString, IntoStaticStr)]
pub enum Alg {
    ES256,
    EdDSA,
}

#[async_trait]
pub trait Signer: Sync + Send {
    fn alg(&self) -> Alg;

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error>;
}

#[async_trait]
pub trait Verifier: Sync + Send {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

pub trait Key {
    fn pub_key(&self) -> Vec<u8>;

    fn jwk(&self) -> Option<ssi::jwk::JWK>;
}

#[async_trait]
pub trait SigningKey: Key + Signer {}

#[async_trait]
pub trait VerifyingKey: Key + Verifier {}

#[async_trait]
pub trait Suite: SigningKey + VerifyingKey + Sized {
    fn gen() -> Vec<u8>;

    fn from_secret(vec: Vec<u8>) -> Result<Self, Error>;
}