use crate::kms::js::JsKeyHandle;
use crate::utils::to_json_object;
use crate::vc::JsonObject;
use agent_sdk::did::didweb::DIDWeb;
use napi::{Error, Result};
use napi_derive::napi;

#[napi(js_name = "DIDWeb")]
pub struct JsDIDWeb;

#[allow(clippy::new_without_default)]
#[napi]
impl JsDIDWeb {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self
    }

    #[napi]
    pub fn generate_did_from_url(&self, url: String) -> Result<String> {
        DIDWeb::generate_did_from_url(&url)
            .map(|v| v.to_string())
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn generate_did_document(&self, did: String, key: JsKeyHandle) -> Result<JsonObject> {
        DIDWeb::generate_did_document(&did, &key)
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(to_json_object)
    }
}
