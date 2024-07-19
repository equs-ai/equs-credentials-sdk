use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

use crate::core_::crypto;

// Error handling
#[derive(Debug)]
pub enum Error {
    Unknown,
    Crypto(crypto::Error),
}

// Basic types definitions

pub type KeyID = String;

#[derive(Debug, PartialEq)]
pub enum KeyType {
    Ed25519,
    P256,
    // etc
}

impl FromStr for KeyType {
    type Err = ();

    fn from_str(input: &str) -> Result<KeyType, Self::Err> {
        match input {
            "Ed25519" => Ok(KeyType::Ed25519),
            "P256" => Ok(KeyType::P256),
            _ => Err(()),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

// Method options
#[derive(Default)]
pub struct CreateOptions {}

pub trait KeyHandle: crypto::Signer + crypto::Verifier {}

pub trait Kms<KH>
where
    KH: KeyHandle,
{
    async fn create(&mut self, kt: &KeyType, opts: CreateOptions) -> Result<KeyID, Error>;

    async fn get(&self, kid: &KeyID) -> Result<KH, Error>;
}