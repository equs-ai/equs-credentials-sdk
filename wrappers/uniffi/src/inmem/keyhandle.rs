use crate::common::{Error, Result};
use crate::key_handle::KeyHandle;
use crate::vc::Alg;
use async_trait::async_trait;
use equs_sdk::crypto::{Key, Signer, Verifier};
use equs_sdk::inmem::kms::KeyHandle as EqusSdkInMemKeyHandle;

#[derive(Clone)]
pub struct InMemKeyHandle {
    inner: EqusSdkInMemKeyHandle,
}

impl InMemKeyHandle {
    pub fn new(kh: EqusSdkInMemKeyHandle) -> Self {
        Self { inner: kh }
    }
    pub fn inner(&self) -> &dyn Key {
        &self.inner
    }
}

#[async_trait]
impl KeyHandle for InMemKeyHandle {
    fn pub_key(&self) -> Result<Vec<u8>> {
        self.inner.pub_key().map_err(|e| {
            Error::KeyHandle(format!(
                "InMemKeyHandle pub key error: {:#?}",
                e.to_string()
            ))
        })
    }

    fn jwk(&self) -> Option<String> {
        self.inner
            .jwk()
            .as_ref()
            .and_then(|jwk| serde_json::to_string(jwk).ok())
    }
    fn alg(&self) -> Alg {
        self.inner.alg()
    }

    async fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        self.inner.sign(payload.as_slice()).await.map_err(|e| {
            Error::KeyHandle(format!("InMemKeyHandle sign error: {:#?}", e.to_string()))
        })
    }

    async fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        self.inner
            .verify(data.as_slice(), signature.as_slice())
            .await
            .map_err(|e| {
                Error::KeyHandle(format!("InMemKeyHandle verify error: {:#?}", e.to_string()))
            })
    }
}
