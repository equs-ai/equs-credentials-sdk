// Error handling
pub enum KmsError {}

// Basic types definitions

pub type KeyID = String;

pub enum KeyType {
    ED25519,
    // etc
}

// Method options
pub struct CreateOptions {}

pub trait Signer {
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
    async fn create(key_type: KeyType, options: CreateOptions) -> Result<KeyID, KmsError>;

    async fn get(key_id: KeyID) -> Result<KH, KmsError>;

    async fn pub_key(key_id: KeyID) -> Result<impl PubKey, KmsError>;
}