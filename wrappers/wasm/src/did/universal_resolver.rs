use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::did::{DIDResolution, DIDVerificationMethod};
use crate::utils;

/// An Universal `DID` resolver.
///
/// # Supported methods
///
/// `did:key`
/// `did:peer`
/// `did:web`
#[wasm_bindgen]
pub struct UniversalDIDResolver(UniversalResolver);

#[wasm_bindgen]
impl UniversalDIDResolver {
    /// Creates a new Universal `DID` resolver.
    #[wasm_bindgen(constructor)]
    pub fn new() -> UniversalDIDResolver {
        let resolver = UniversalResolver::default();

        UniversalDIDResolver(resolver)
    }

    /// Resolves a DID and extracts one of the verification methods it defines.
    ///
    /// This will return the first verification method found, although users
    /// should not expect the DID documents to always list verification methods
    /// in the same order.
    #[wasm_bindgen(js_name = resolveVerificationMethod)]
    pub async fn resolve_verification_method(
        &self,
        did: String,
    ) -> Result<Option<DIDVerificationMethod>, JsError> {
        self.0
            .resolve_into_any_verification_method(&DIDBuf::from_str(&did).map_err(JsError::from)?)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?
            .map(utils::convert_to_opaque_object_unchecked)
            .transpose()
    }

    /// Resolves a DID.
    ///
    /// Fetches the DID document referenced by the input DID.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    #[wasm_bindgen]
    pub async fn resolve(&self, did: String) -> Result<DIDResolution, JsError> {
        let output = self
            .0
            .resolve(&DIDBuf::from_str(&did).map_err(JsError::from)?)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        let json_value = serde_json::json!({
            "document": output.document,
            "metadata": output.metadata,
            "document_metadata": output.document_metadata,
        });

        utils::convert_to_opaque_object_unchecked(json_value)
    }
}
