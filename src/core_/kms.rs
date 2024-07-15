use std::fmt;

// Error handling
#[derive(fmt::Debug)]
pub enum KmsError {}

// Basic types definitions

pub type KeyID = String;

pub enum KeyType {
    ED25519,
    // etc
}

pub enum Alg {
    ES256,
}

// Method options
pub struct CreateOptions {}

pub trait Signer {
    fn alg() -> Alg;

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, KmsError>;
}

pub trait Verifier {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), KmsError>;
}

pub trait KeyHandle: Signer + Verifier {}

pub trait PubKey {}

pub trait Kms<KH>
where
    KH: KeyHandle,
{
    async fn create(&self, key_type: KeyType, options: CreateOptions) -> Result<KeyID, KmsError>;

    async fn get(&self, kid: &KeyID) -> Result<KH, KmsError>;

    async fn pub_key(&self, key_id: &KeyID) -> Result<Box<dyn PubKey>, KmsError>;
}