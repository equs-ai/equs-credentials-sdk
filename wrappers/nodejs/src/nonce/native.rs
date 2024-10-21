use crate::nonce::JsNonceData;
use agent_sdk::nonce::NonceGenerator;
use napi_derive::napi;
use std::sync::Arc;
use time::Duration;

#[derive(Clone)]
#[napi]
pub struct NativeNonceGenerator(Arc<dyn NonceGenerator>);

#[napi]
impl NativeNonceGenerator {
    pub fn from<NG: NonceGenerator + 'static>(nonce_generator: NG) -> NativeNonceGenerator {
        NativeNonceGenerator(Arc::new(nonce_generator))
    }

    pub fn inner(&self) -> &dyn NonceGenerator {
        self.0.as_ref()
    }

    #[napi]
    pub async fn generate(&self) -> napi::Result<String> {
        self.0
            .generate()
            .await
            .map(|nonce| nonce.secret().to_string())
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn with_expiration(&self, expiration: i64) -> napi::Result<JsNonceData> {
        self.0
            .with_expiration(Duration::seconds(expiration))
            .await
            .map(Into::into)
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }
}
