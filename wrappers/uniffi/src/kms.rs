use crate::common::Result;
use crate::key_handle::WrappedKeyHandle;
use async_trait::async_trait;
use equs_sdk::kms::{CreateOptions, CreationSnafu, GetSnafu, KeyID};
use equs_sdk::kms::{Error as EqusSdkError, Result as EqusSdkResult};
pub(crate) use equs_sdk::kms::{KeyType, Kms as EqusSdkKms};
use std::fmt::Debug;
use std::sync::Arc;

#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    P256,
    K256,
    Bls12381,
}

/// Key management.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait Kms: Send + Sync + Debug {
    /// Generates a key of the given type and persists it.
    ///
    /// # Arguments
    /// * `kt` - the key type to generate
    ///
    /// # Returns
    /// The key identifier, unique within this `Kms` and valid for `get` while the key exists.
    ///
    /// # Errors
    /// * `Error.Kms` - unsupported key type, or the key could not be created
    async fn create(&self, kt: KeyType) -> Result<String>;

    /// Returns the handle for a key identifier.
    ///
    /// # Arguments
    /// * `kid` - an identifier previously returned by `create`
    ///
    /// # Returns
    /// The handle for that key.
    ///
    /// # Errors
    /// * `Error.Kms` - no key exists under `kid`
    async fn get(&self, kid: String) -> Result<WrappedKeyHandle>;

    /// Returns the handle for the key with the given public key.
    ///
    /// # Arguments
    /// * `public_key` - raw public key bytes, as `KeyHandle.pubKey` returns them
    ///
    /// # Returns
    /// The handle for the matching key.
    ///
    /// # Errors
    /// * `Error.Kms` - no key matches
    async fn get_by_public_key(&self, public_key: Vec<u8>) -> Result<WrappedKeyHandle>;
}

#[derive(Debug, Clone)]
pub struct WrappedKms {
    inner: Arc<dyn Kms>,
}

impl WrappedKms {
    pub fn new(kms: Arc<dyn Kms>) -> Self {
        Self { inner: kms }
    }
    pub fn inner(&self) -> Arc<dyn Kms> {
        self.inner.to_owned()
    }
}

#[async_trait]
impl EqusSdkKms<WrappedKeyHandle> for WrappedKms {
    async fn create(&self, kt: KeyType, _: CreateOptions) -> EqusSdkResult<String> {
        self.inner().create(kt).await.map_err(|e| {
            CreationSnafu {
                details: e.to_string(),
            }
            .build()
        })
    }

    async fn get(&self, kid: &KeyID) -> EqusSdkResult<WrappedKeyHandle> {
        let kh = self.inner().get(kid.to_owned()).await.map_err(|e| {
            GetSnafu {
                details: e.to_string(),
            }
            .build()
        })?;
        Ok(kh)
    }

    async fn get_by_public_key(&self, public_key: &[u8]) -> EqusSdkResult<WrappedKeyHandle> {
        let kh = self
            .inner()
            .get_by_public_key(public_key.to_owned())
            .await
            .map_err(|e| EqusSdkError::Get {
                details: e.to_string(),
            })?;
        Ok(kh)
    }
}

#[cfg(debug_assertions)]
#[uniffi::export]
fn wrap_kms_for_tests(kms: Arc<dyn Kms>) -> Arc<dyn Kms> {
    WrappedKms::new(kms).inner()
}
