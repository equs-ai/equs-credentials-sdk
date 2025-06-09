use crate::common::Result;
use crate::vc::Alg;
use agent_sdk::crypto::{
    Error as ASDKError, Key, Result as ASDKResult, Signer, SigningKey, SigningSnafu,
    VerificationSnafu, Verifier, VerifyingKey, JWK,
};
use agent_sdk::kms::KeyHandle as ASDKKeyHandle;
use async_trait::async_trait;
use std::sync::Arc;

#[uniffi::export(with_foreign)]
#[async_trait]
pub trait KeyHandle: Send + Sync {
    fn pub_key(&self) -> Result<Vec<u8>>;
    fn jwk(&self) -> Option<String>;
    fn alg(&self) -> Alg;
    async fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>>;
    async fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<()>;
}

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
    fn pub_key(&self) -> ASDKResult<Vec<u8>> {
        Ok(self
            .inner()
            .pub_key()
            .map_err(|_| ASDKError::KeyNotSupported {
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

    async fn sign(&self, payload: &[u8]) -> ASDKResult<Vec<u8>> {
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
    async fn verify(&self, data: &[u8], signature: &[u8]) -> ASDKResult<()> {
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

impl ASDKKeyHandle for WrappedKeyHandle {}

#[uniffi::export]
fn wrap_key_handle_for_tests(key_handle: Arc<dyn KeyHandle>) -> Arc<dyn KeyHandle> {
    WrappedKeyHandle::new(key_handle).inner()
}
