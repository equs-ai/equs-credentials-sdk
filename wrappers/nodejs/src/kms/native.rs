use agent_sdk::crypto::{SigningKey, VerifyingKey};
use agent_sdk::kms::{CreateOptions, KeyHandle, Kms};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use std::sync::Arc;

use crate::kms::{JsKeyType, KeyHandleWrapper, KmsWrapper};
use crate::vc::core::JsAlg;

#[derive(Clone)]
#[napi]
pub struct NativeKeyHandle(Arc<dyn SigningKey>, Arc<dyn VerifyingKey>);

#[napi]
impl NativeKeyHandle {
    #[napi]
    pub fn pub_key(&self) -> napi::Result<Vec<u8>> {
        self.0
            .pub_key()
            .map(Into::into)
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub fn jwk(&self) -> Option<String> {
        self.0
            .jwk()
            .and_then(|value| serde_json::to_string(&value).ok())
    }

    #[napi]
    pub fn alg(&self) -> napi::Result<JsAlg> {
        self.0.alg().try_into()
    }

    #[napi]
    pub async fn sign(&self, payload: &[u8]) -> napi::Result<Uint8Array> {
        self.0
            .sign(payload)
            .await
            .map(Into::into)
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn verify(&self, data: &[u8], signature: &[u8]) -> napi::Result<()> {
        self.1
            .verify(data, signature)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }
}

#[derive(Clone)]
#[napi]
pub struct NativeKms(Arc<dyn Kms<KeyHandleWrapper>>);

#[napi]
impl NativeKms {
    pub fn from<KH: KeyHandle + 'static, KMS: Kms<KH> + 'static>(kms: KMS) -> NativeKms {
        NativeKms(Arc::new(KmsWrapper(Arc::new(kms))))
    }

    pub fn inner(&self) -> &dyn Kms<KeyHandleWrapper> {
        self.0.as_ref()
    }

    #[napi]
    pub async fn create(&self, kt: JsKeyType) -> napi::Result<String> {
        self.0
            .create(kt.into(), CreateOptions::default())
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn get(&self, kid: String) -> napi::Result<NativeKeyHandle> {
        self.0
            .get(&kid)
            .await
            .map(Into::into)
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }
}

impl From<KeyHandleWrapper> for NativeKeyHandle {
    fn from(value: KeyHandleWrapper) -> Self {
        NativeKeyHandle(value.0, value.1)
    }
}
