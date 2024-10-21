use crate::nonce::{JsNonceGenerator, NativeNonceGenerator};
use napi_derive::napi;

#[napi]
pub fn wrap_js_nonce_generator(nonce_generator: JsNonceGenerator) -> NativeNonceGenerator {
    NativeNonceGenerator::from(nonce_generator)
}
