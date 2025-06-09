use super::super::kms::KeyType;
use crate::common::{Error, Result};
use crate::inmem::keyhandle::InMemKeyHandle;
use crate::key_handle::WrappedKeyHandle;
use crate::kms::Kms;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::kms::{CreateOptions, Kms as ASDKKms};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(uniffi::Object, Debug)]
pub struct InMemKms(LocalKms);

#[uniffi::export()]
impl InMemKms {
    #[uniffi::constructor]
    fn new() -> Self {
        InMemKms(LocalKms::new())
    }
}

#[uniffi::export()]
#[async_trait]
impl Kms for InMemKms {
    async fn create(&self, kt: KeyType) -> Result<String> {
        self.0
            .create(kt, CreateOptions::default())
            .await
            .map_err(|e| Error::Kms(format!("InMemKms create error: {:#?}", e.to_string())))
    }

    async fn get(&self, kid: String) -> Result<WrappedKeyHandle> {
        let kh = self
            .0
            .get(&kid)
            .await
            .map_err(|e| Error::Kms(format!("InMemKms get error: {:#?}", e.to_string())))?;

        Ok(WrappedKeyHandle::new(Arc::new(InMemKeyHandle::new(kh))))
    }

    async fn get_by_public_key(&self, public_key: Vec<u8>) -> Result<WrappedKeyHandle> {
        let kh = self.0.get_by_public_key(&public_key).await.map_err(|e| {
            Error::Kms(format!(
                "InMemKms get_by_public_key error {:#?}",
                e.to_string()
            ))
        })?;

        Ok(WrappedKeyHandle::new(Arc::new(InMemKeyHandle::new(kh))))
    }
}

impl InMemKms {
    pub fn inner(&self) -> LocalKms {
        self.0.clone()
    }
}
