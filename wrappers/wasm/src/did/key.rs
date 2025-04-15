use crate::kms::{JsKeyHandle, KeyHandle};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

/// A general `did:key` service.
///
/// Supports generation of `did:keys`.
#[wasm_bindgen]
pub struct DIDKey;

#[wasm_bindgen]
impl DIDKey {
    /// Creates a new `did:key` service.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    /// Create a `did:key`.
    ///
    /// # Arguments
    ///
    /// * `key` - a key to include in `did:key`.
    ///
    /// # Returns
    ///
    /// A new `did:key` based on the `key` on success.
    ///
    /// # Errors
    ///
    /// * Returns an error if the underlying DID generation process fails.
    pub fn generate(&self, key: KeyHandle) -> Result<String, JsError> {
        agent_sdk::did::didkey::DIDKey::generate(JsKeyHandle::new(key))
            .map(|v| v.to_string())
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }
}
