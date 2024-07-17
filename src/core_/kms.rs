use std::fmt;

use crate::core_::crypto;

// Error handling
#[derive(fmt::Debug)]
pub enum KmsError {}

// Basic types definitions

pub type KeyID = String;

pub enum KeyType {
    ED25519,
    // etc
}

// Method options
pub struct CreateOptions {}

pub trait KeyHandle: crypto::Signer + crypto::Verifier {}

pub trait PubKey {}

pub trait Kms<KH>
where
    KH: KeyHandle,
{
    async fn create(&self, key_type: KeyType, options: CreateOptions) -> Result<KeyID, KmsError>;

    async fn get(&self, kid: &KeyID) -> Result<KH, KmsError>;

    async fn pub_key(&self, key_id: &KeyID) -> Result<Box<dyn PubKey>, KmsError>;
}