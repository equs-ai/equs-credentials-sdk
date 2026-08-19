use crate::common::Result;
use agent_sdk::nonce::GenerateSnafu;
use agent_sdk::nonce::ValidateSnafu;
use agent_sdk::nonce::{Nonce, NonceHandler as ASDKNonceHandler};
use async_trait::async_trait;
use std::sync::Arc;
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait NonceHandler: Send + Sync {
    async fn generate(&self) -> Result<String>;

    async fn validate(&self, nonce: String) -> Result<bool>;
}

#[derive(Clone)]
pub struct WrappedNonceHandler {
    inner: Arc<dyn NonceHandler>,
}

impl WrappedNonceHandler {
    pub fn new(nh: Arc<dyn NonceHandler>) -> Self {
        Self { inner: nh }
    }

    pub fn inner(&self) -> Arc<dyn NonceHandler> {
        self.inner.to_owned()
    }
}

#[async_trait]
impl ASDKNonceHandler for WrappedNonceHandler {
    async fn generate(&self) -> agent_sdk::nonce::Result<Nonce> {
        self.inner
            .generate()
            .await
            .map(Nonce::from_secret)
            .map_err(|e| {
                GenerateSnafu {
                    details: format!("{}", e),
                }
                .build()
            })
    }

    async fn validate(&self, nonce: &Nonce) -> agent_sdk::nonce::Result<bool> {
        self.inner
            .validate(nonce.secret().to_string())
            .await
            .map_err(|e| {
                ValidateSnafu {
                    details: format!("{}", e),
                }
                .build()
            })
    }

    async fn invalidate(&self, _nonces: &[Nonce]) -> agent_sdk::nonce::Result<()> {
        // These bindings expose the holder and verifier, not the issuer service that spends nonces.
        Ok(())
    }
}
