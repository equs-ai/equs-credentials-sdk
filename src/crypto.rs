use std::ops::Deref;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use ssi::jwk::JWK;
use strum_macros::{Display, EnumString, IntoStaticStr};

/// `Crypto` Error.
///
/// Enumerates general errors expected during `Crypto` operations.
#[derive(Debug, thiserror::Error, IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("Key not supported: {0}")]
    KeyNotSupported(String),
    #[error("Alg not supported: {0}")]
    AlgNotSupported(String),
    #[error("Signing error: {0}")]
    Signature(String),
    #[error("Verifying error: {0}")]
    Verification(String),
    #[error("Key generation error: {0}")]
    KeyGeneration(String),
}

/// `Result` alias for Crypto-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// Enum with supported `Crypto` algorithms.
///
/// *NOTE*: more algs to be supported later.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[derive(Display, EnumString, IntoStaticStr)]
pub enum Alg {
    ES256,
    EdDSA,
}

/// An async `Signer` interface.
///
/// Exposes primitives to sign a binary payload.
#[async_trait]
pub trait Signer: Sync + Send {
    /// Returns algorithm of the signer.
    ///
    /// # Returns
    ///
    /// An `Alg` enum value.
    fn alg(&self) -> Alg;

    /// Sign the provided binary payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - a slice of bytes to be signed.
    ///
    /// # Returns
    ///
    /// A signed `payload` on success.
    ///
    /// # Errors
    ///
    /// * [Error::Signature] - fails to sign a payload.
    /// * [Error::AlgNotSupported] - algorithm is not supported.
    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

/// An async `Verifier` interface.
///
/// Exposes primitives to verify that a binary data was correctly signed.
#[async_trait]
pub trait Verifier: Sync + Send {
    /// Verify that a signed data was signed using the provided signature.
    ///
    /// # Arguments
    ///
    /// * `data` - a payload to be verified against the signature.
    /// * `signature` - the corresponding signature.
    ///
    /// # Errors
    ///
    /// * [Error::Verification] - verification failed.
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()>;
}

/// A general `Key` interface.
///
/// Exposes the public key and the JWK if suitable.
pub trait Key: Sync + Send {
    /// Returns the public key for the corresponding handle.
    ///
    /// # Returns
    ///
    /// Public key bytes.
    ///
    /// # Errors
    ///
    /// * [Error::KeyNotSupported] - key is not supported.
    fn pub_key(&self) -> Result<Vec<u8>>;

    /// Returns the public key in JWK form if it's supported.
    ///
    /// # Returns
    ///
    /// `Some(jwk)` if the public key can be represented as JWK.
    /// `None` if the JWK-form is not supported.
    fn jwk(&self) -> Option<JWK>;
}

impl Key for Box<dyn Key> {
    fn pub_key(&self) -> Result<Vec<u8>> {
        self.deref().pub_key()
    }

    fn jwk(&self) -> Option<JWK> {
        self.deref().jwk()
    }
}

/// Utility trait that combines [Signer] and [Key].
#[async_trait]
pub trait SigningKey: Key + Signer {}

/// Utility trait that combines [Verifier] and [Key].
#[async_trait]
pub trait VerifyingKey: Key + Verifier {}

/// A crypto `Suite` with support of signing/verification.
///
/// Supports extra methods to generate key material.
#[async_trait]
pub trait Suite: SigningKey + VerifyingKey + Sized {
    /// Generate a private key.
    ///
    /// # Returns
    ///
    /// Private key bytes.
    fn gen() -> Vec<u8>;

    /// Build a `Suite` from a secret key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - private key bytes.
    ///
    /// # Returns
    ///
    /// A `Suite` for the provided key.
    ///
    /// # Errors
    ///
    /// * [Error::KeyNotSupported] - key is not supported.
    /// * [Error::AlgNotSupported] - algorithm is not supported.
    /// * [Error::KeyGeneration] - fails to generate a key.
    fn from_secret(bytes: Vec<u8>) -> Result<Self>;
}