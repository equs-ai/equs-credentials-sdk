use crate::did::{DIDDocument, VerificationMethodKey};
use crate::utils::convert_to_opaque_object_unchecked;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

/// A general `did:web` service.
///
/// Supports generation of `did:web`.
#[wasm_bindgen]
pub struct DIDWeb;

#[wasm_bindgen]
impl DIDWeb {
    /// Creates a new `did:web` service.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    /// Generate a `did:web` from a URL.
    ///
    /// # Arguments
    ///
    /// * `url` - a URL for which the [DID] is generated.
    ///
    /// # Returns
    ///
    /// A new `did:web` based on the `url` on success.
    ///
    /// # Errors
    ///
    /// * Returns an error if the underlying DID generation process fails.
    #[wasm_bindgen(js_name = generateDidFromUrl)]
    pub fn generate_did_from_url(&self, url: String) -> Result<String, JsError> {
        equs_sdk::did::didweb::DIDWeb::generate_did_from_url(&url)
            .map(|v| v.to_string())
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }

    /// Generate a [DIDDocument] for a `DID`.
    ///
    /// # Arguments
    ///
    /// * `did` - a `DID` for which the [DIDDocument] is generated.
    /// - `keys`: [VerificationMethodKey] objects representing the cryptographic keys
    ///   that will be embedded in the DID document.
    ///
    /// # Returns
    ///
    /// A new [DIDDocument].
    ///
    /// # Errors
    ///
    /// * Returns an error if the provided key type is not supported.
    #[wasm_bindgen(js_name = generateDidDocument)]
    pub fn generate_did_document(
        &self,
        did: String,
        keys: Vec<VerificationMethodKey>,
    ) -> Result<DIDDocument, JsError> {
        let keys = keys
            .iter()
            .map(|vm_key| equs_sdk::did::VerificationMethodKey {
                key: &vm_key.key,
                verification_relationships: vm_key
                    .verification_relationships
                    .iter()
                    .map(|v| v.clone())
                    .collect(),
            })
            .collect::<Vec<_>>();

        equs_sdk::did::didweb::DIDWeb::generate_did_document(&did, &keys)
            .map_err(|err| JsError::new(&format!("{:?}", err)))
            .and_then(convert_to_opaque_object_unchecked)
    }
}
