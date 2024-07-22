use std::fmt;

use p256::ecdsa::signature;

// Error handling
#[derive(fmt::Debug)]
pub enum Error {
    Unknown,
    Signature(signature::Error),
    Verification(signature::Error),
    KeyCreation,
}

pub enum Alg {
    ES256,
    ED25519,
}

pub trait Signer {
    fn alg(&self) -> Alg;

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait Verifier {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

pub trait Suite: Signer + Verifier + Sized {
    fn gen() -> Vec<u8>;

    fn from_secret(vec: Vec<u8>) -> Result<Self, Error>;

    fn pub_key(&self) -> Vec<u8>;
}