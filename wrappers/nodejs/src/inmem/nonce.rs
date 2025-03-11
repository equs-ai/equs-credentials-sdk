use crate::nonce::JsNonceData;
use agent_sdk::nonce::NonceGenerator;
use napi::{Error, Result};
use napi_derive::napi;
use time::Duration;

#[napi]
pub struct LocalNonceGenerator(agent_sdk::inmem::nonce::LocalNonceGenerator);

#[napi]
impl LocalNonceGenerator {
    #[napi(constructor)]
    pub fn new() -> Self {
        let nonce_generator = agent_sdk::inmem::nonce::LocalNonceGenerator::default();
        LocalNonceGenerator(nonce_generator)
    }
    #[napi]
    pub async fn generate(&self) -> Result<String> {
        let nonce = self
            .0
            .generate()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(nonce.secret().to_string())
    }

    #[napi]
    pub async fn with_expiration(&self, expiration: i64) -> Result<JsNonceData> {
        self.0
            .with_expiration(Duration::seconds(expiration))
            .await
            .map(Into::into)
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }
}

impl Default for LocalNonceGenerator {
    fn default() -> Self {
        let nonce_generator = agent_sdk::inmem::nonce::LocalNonceGenerator::default();
        LocalNonceGenerator(nonce_generator)
    }
}
