use agent_sdk::nonce::NonceHandler;
use napi::{Error, Result};
use napi_derive::napi;

#[napi]
pub struct LocalNonceHandler(agent_sdk::inmem::nonce::LocalNonceHandler);

#[napi]
impl LocalNonceHandler {
    #[napi(constructor)]
    pub fn new() -> Self {
        let nonce_generator = agent_sdk::inmem::nonce::LocalNonceHandler::default();
        LocalNonceHandler(nonce_generator)
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
    pub async fn validate(&self, nonce: String) -> Result<bool> {
        let validation = self
            .0
            .validate(&agent_sdk::nonce::Nonce::from_secret(nonce))
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(validation)
    }
}

impl Default for LocalNonceHandler {
    fn default() -> Self {
        let nonce_generator = agent_sdk::inmem::nonce::LocalNonceHandler::default();
        LocalNonceHandler(nonce_generator)
    }
}
