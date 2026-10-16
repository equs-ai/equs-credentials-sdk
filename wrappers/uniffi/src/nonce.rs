use crate::common::Result;
use async_trait::async_trait;
use equs_sdk::nonce::GenerateSnafu;
use equs_sdk::nonce::ValidateSnafu;
use equs_sdk::nonce::{Nonce, NonceHandler as EqusSdkNonceHandler};
use std::sync::Arc;

/// Issues and validates the one-time challenges that bind a proof to a single exchange; its store
/// of active nonces must be shared by every instance, and nonces are never spent through it.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait NonceHandler: Send + Sync {
    /// Issues a fresh nonce and records it as active.
    ///
    /// # Returns
    /// The nonce, drawn from a cryptographically secure random source.
    ///
    /// # Errors
    /// * `Error` - the nonce could not be issued
    async fn generate(&self) -> Result<String>;

    /// Reports whether a nonce is active, without consuming it; the same nonce may be validated
    /// more than once within a single exchange.
    ///
    /// # Arguments
    /// * `nonce` - the nonce to validate
    ///
    /// # Returns
    /// `true` only for a nonce this handler issued that has not expired.
    ///
    /// # Errors
    /// * `Error` - the nonce store could not be reached
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
impl EqusSdkNonceHandler for WrappedNonceHandler {
    async fn generate(&self) -> equs_sdk::nonce::Result<Nonce> {
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

    async fn validate(&self, nonce: &Nonce) -> equs_sdk::nonce::Result<bool> {
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

    async fn invalidate(&self, _nonces: &[Nonce]) -> equs_sdk::nonce::Result<()> {
        // These bindings expose the holder and verifier, not the issuer service that spends nonces.
        Ok(())
    }
}
