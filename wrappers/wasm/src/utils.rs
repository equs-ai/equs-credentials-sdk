use crate::crypto::KeyMetadata;
use crate::vc::{Credential, CredentialMetadata, JsCredential};
use equs_sdk::vc::HasClaims;
use equs_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use js_sys::JSON;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsError, JsValue};

#[wasm_bindgen]
extern "C" {

    #[wasm_bindgen(typescript_type = "Claims")]
    pub type Claims;
}

#[wasm_bindgen(js_name = resolveMetadata)]
pub async fn resolve_metadata(
    credential: Credential,
    metadata: KeyMetadata,
) -> Result<CredentialMetadata, JsError> {
    let js_credential: JsCredential = convert_to_rust_object(credential)?;
    let credential = js_credential.try_into()?;
    let metadata = convert_to_rust_object(metadata)?;

    let result =
        DefaultMetadataProcessor::resolve_metadata(&credential, metadata).map_err(js_err)?;
    let credential_metadata: equs_sdk::vc::CredentialMetadata =
        result.try_into().map_err(js_err)?;

    convert_to_opaque_object_unchecked(credential_metadata)
}

#[wasm_bindgen(js_name = parseClaims)]
pub async fn parse_claims(credential: Credential) -> Result<Claims, JsError> {
    let js_credential: JsCredential = convert_to_rust_object(credential)?;
    let credential: equs_sdk::vc::Credential = js_credential.try_into()?;
    let claims = credential.parse_claims().map_err(js_err)?;

    convert_to_opaque_object_unchecked(claims)
}

#[allow(unused)]
pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[allow(unused)]
pub fn js_value_to_string(value: JsValue) -> String {
    if let Some(s) = value.as_string() {
        s
    } else if let Ok(json) = JSON::stringify(&value) {
        json.as_string().unwrap_or_else(|| format!("{:?}", value))
    } else {
        format!("{:?}", value)
    }
}

pub fn get_property(value: &JsValue, key: &str) -> Result<JsValue, JsError> {
    js_sys::Reflect::get(value, &JsValue::from_str(key))
        .map_err(|err| JsError::new(&js_value_to_string(err)))
}

pub fn convert_to_rust_object<T: JsCast, R: DeserializeOwned>(value: T) -> Result<R, JsError> {
    serde_wasm_bindgen::from_value(value.into()).map_err(JsError::from)
}

#[allow(unused)]
pub fn convert_to_opaque_object<T: Serialize, R: JsCast>(value: T) -> Result<R, JsError> {
    let js_value = value
        .serialize(&Serializer::json_compatible())
        .map_err(JsError::from)?;

    js_value
        .dyn_into()
        .map_err(|err| JsError::new(&format!("Failed to convert: {}", js_value_to_string(err))))
}

pub fn convert_to_opaque_object_unchecked<T: Serialize, R: JsCast>(value: T) -> Result<R, JsError> {
    value
        .serialize(&Serializer::json_compatible())
        .map(|value| value.unchecked_into())
        .map_err(JsError::from)
}

pub(crate) fn js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}
