use crate::kms::JsKeyHandle;
use agent_sdk::did::didkey::DIDKey;
use napi::{Error, Result};
use napi_derive::napi;

#[napi(js_name = "DIDKey")]
pub struct JsDIDKey;

#[allow(clippy::new_without_default)]
#[napi]
impl JsDIDKey {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self
    }

    #[napi]
    pub fn generate(&self, key: JsKeyHandle) -> Result<String> {
        DIDKey::generate(key)
            .map(|v| v.to_string())
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}
