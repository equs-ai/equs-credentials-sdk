use crate::common::Result;
use crate::vc::Alg;
use async_trait::async_trait;
use equs_sdk::crypto::{
    Error as EqusSdkError, JWK, Key, Result as EqusSdkResult, Signer, SigningKey, SigningSnafu,
    VerificationSnafu, Verifier, VerifyingKey,
};
use equs_sdk::kms::KeyHandle as EqusSdkKeyHandle;
use std::sync::Arc;

/// Signing and verification for a single key; must be safe for concurrent use and describe the same
/// key for its lifetime.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait KeyHandle: Send + Sync {
    /// Returns the raw public key bytes for this key.
    ///
    /// # Returns
    /// The public key in the encoding the key type prescribes.
    ///
    /// # Errors
    /// * `Error.KeyHandle` - the public key could not be read
    fn pub_key(&self) -> Result<Vec<u8>>;

    /// Returns the public key as a serialized JWK.
    ///
    /// # Returns
    /// A JSON object, or `null` if this key has no JWK form; a value that does not parse is
    /// treated as absent.
    fn jwk(&self) -> Option<String>;

    /// Returns the JWS algorithm this key signs with.
    ///
    /// # Returns
    /// The algorithm that fixes the `alg` header of every proof built from this key.
    fn alg(&self) -> Alg;

    /// Signs the payload with this key.
    ///
    /// # Arguments
    /// * `payload` - the exact bytes to sign, not hashed, prefixed or re-encoded
    ///
    /// # Returns
    /// The raw signature, in the algorithm's fixed-width form, not DER.
    ///
    /// # Errors
    /// * `Error.KeyHandle` - signing failed
    async fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>>;

    /// Verifies a signature over the given data using this key's public part.
    ///
    /// # Arguments
    /// * `data` - the signed bytes
    /// * `signature` - the signature to verify
    ///
    /// # Errors
    /// * `Error.KeyHandle` - the signature is invalid, or verification failed
    async fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<()>;
}

// Must be `uniffi::Record` (not Object) so Kotlin/Swift Kms implementations can
// construct it directly when returning from `Kms::get()`. An Object would be
// opaque and un-constructable on the foreign side.
#[derive(Clone, uniffi::Record)]
pub struct WrappedKeyHandle {
    inner: Arc<dyn KeyHandle>,
}

impl WrappedKeyHandle {
    pub fn new(kh: Arc<dyn KeyHandle>) -> Self {
        Self { inner: kh }
    }
    pub fn inner(&self) -> Arc<dyn KeyHandle> {
        self.inner.to_owned()
    }
}

#[async_trait]
impl KeyHandle for WrappedKeyHandle {
    fn pub_key(&self) -> Result<Vec<u8>> {
        self.inner().pub_key()
    }

    fn jwk(&self) -> Option<String> {
        self.inner().jwk()
    }

    fn alg(&self) -> Alg {
        self.inner().alg()
    }

    async fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        self.inner().sign(payload).await
    }

    async fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        self.inner().verify(data, signature).await
    }
}

impl SigningKey for WrappedKeyHandle {}

impl Key for WrappedKeyHandle {
    fn pub_key(&self) -> EqusSdkResult<Vec<u8>> {
        Ok(self
            .inner()
            .pub_key()
            .map_err(|_| EqusSdkError::KeyNotSupported {
                type_: "public".to_string(),
            }))?
    }

    fn jwk(&self) -> Option<JWK> {
        self.inner()
            .jwk()
            .as_ref()
            .and_then(|jwk| serde_json::from_str(jwk).ok())
    }
}

#[async_trait]
impl Signer for WrappedKeyHandle {
    fn alg(&self) -> Alg {
        self.inner().alg()
    }

    async fn sign(&self, payload: &[u8]) -> EqusSdkResult<Vec<u8>> {
        self.inner().sign(payload.to_vec()).await.map_err(|e| {
            SigningSnafu {
                details: e.to_string(),
            }
            .build()
        })
    }
}

impl VerifyingKey for WrappedKeyHandle {}

#[async_trait]
impl Verifier for WrappedKeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> EqusSdkResult<()> {
        self.inner()
            .verify(data.to_vec(), signature.to_vec())
            .await
            .map_err(|e| {
                VerificationSnafu {
                    details: e.to_string(),
                }
                .build()
            })
    }
}

impl EqusSdkKeyHandle for WrappedKeyHandle {}

#[cfg(debug_assertions)]
#[uniffi::export]
fn wrap_key_handle_for_tests(key_handle: Arc<dyn KeyHandle>) -> Arc<dyn KeyHandle> {
    WrappedKeyHandle::new(key_handle).inner()
}
