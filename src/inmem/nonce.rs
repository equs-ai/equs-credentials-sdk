use crate::nonce::{Nonce, NonceGenerator, Result};
use async_trait::async_trait;

const NONCE_EXPIRES_IN: i64 = 86440;

#[derive(Default)]
pub struct LocalNonceGenerator {}

#[async_trait]
impl NonceGenerator for LocalNonceGenerator {
    async fn generate(&self) -> Result<Nonce> {
        let bytes: [u8; 32] = rand::random();
        let nonce = Nonce::new(&bytes);

        Ok(nonce)
    }
}
