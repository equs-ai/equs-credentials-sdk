use crate::common::Result;
use crate::key_handle::WrappedKeyHandle;
use agent_sdk::kms::{CreateOptions, CreationSnafu, GetSnafu, KeyID};
use agent_sdk::kms::{Error as ASDKError, Result as ASDKResult};
pub(crate) use agent_sdk::kms::{KeyType, Kms as ASDKKms};
use async_trait::async_trait;
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

#[uniffi::export(with_foreign)]
#[async_trait]
pub trait Kms: Send + Sync + Debug {
    async fn create(&self, kt: KeyType) -> Result<String>;

    async fn get(&self, kid: String) -> Result<WrappedKeyHandle>;

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
impl ASDKKms<WrappedKeyHandle> for WrappedKms {
    async fn create(&self, kt: KeyType, _: CreateOptions) -> ASDKResult<String> {
        self.inner().create(kt).await.map_err(|e| {
            CreationSnafu {
                details: e.to_string(),
            }
            .build()
        })
    }

    async fn get(&self, kid: &KeyID) -> ASDKResult<WrappedKeyHandle> {
        let kh = self.inner().get(kid.to_owned()).await.map_err(|e| {
            GetSnafu {
                details: e.to_string(),
            }
            .build()
        })?;
        Ok(kh)
    }

    async fn get_by_public_key(&self, public_key: &[u8]) -> ASDKResult<WrappedKeyHandle> {
        let kh = self
            .inner()
            .get_by_public_key(public_key.to_owned())
            .await
            .map_err(|e| ASDKError::Get {
                details: e.to_string(),
            })?;
        Ok(kh)
    }
}

#[uniffi::export]
fn wrap_kms_for_tests(kms: Arc<dyn Kms>) -> Arc<dyn Kms> {
    WrappedKms::new(kms).inner()
}
