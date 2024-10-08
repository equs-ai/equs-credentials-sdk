use agent_sdk::nonce::{Nonce, NonceData, NonceGenerator};
use async_trait::async_trait;
use napi_derive::napi;
use std::sync::Arc;
use time::Duration;

#[derive(Clone)]
#[napi]
pub struct NativeNonceGenerator(Arc<dyn NonceGenerator>);

impl NativeNonceGenerator {
    pub fn from<NG: NonceGenerator + 'static>(nonce_generator: NG) -> NativeNonceGenerator {
        let nonce_generator = Arc::new(nonce_generator);
        NativeNonceGenerator(nonce_generator)
    }
}

#[async_trait]
impl NonceGenerator for NativeNonceGenerator {
    async fn generate(&self) -> agent_sdk::nonce::Result<Nonce> {
        self.0.generate().await
    }

    async fn with_expiration(&self, expiration: Duration) -> agent_sdk::nonce::Result<NonceData> {
        self.0.with_expiration(expiration).await
    }
}
