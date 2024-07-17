use std::fmt;

// Error handling
#[derive(fmt::Debug)]
pub enum CryptoError {}

pub enum Alg {
    ES256,
}

pub trait Signer {
    fn alg() -> Alg;

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait Verifier {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}