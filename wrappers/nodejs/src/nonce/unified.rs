use crate::nonce::{JsNonceGenerator, NativeNonceGenerator};
use agent_sdk::nonce;
use agent_sdk::nonce::{Nonce, NonceGenerator};
use async_trait::async_trait;
use napi::Either;

#[derive(Clone)]
pub enum UnifiedNonceGenerator {
    Js(JsNonceGenerator),
    Native(NativeNonceGenerator),
}

#[async_trait]
impl NonceGenerator for UnifiedNonceGenerator {
    async fn generate(&self) -> nonce::Result<Nonce> {
        match self {
            UnifiedNonceGenerator::Js(js) => js.generate().await,
            UnifiedNonceGenerator::Native(native) => native.inner().generate().await,
        }
    }
}

impl From<Either<&NativeNonceGenerator, JsNonceGenerator>> for UnifiedNonceGenerator {
    fn from(value: Either<&NativeNonceGenerator, JsNonceGenerator>) -> Self {
        match value {
            Either::A(native) => UnifiedNonceGenerator::Native(native.clone()),
            Either::B(js) => UnifiedNonceGenerator::Js(js),
        }
    }
}
