use crate::kms::{JsKeyHandle, KeyHandle};
use crate::utils;
use agent_sdk::did::ResolutionOutput;
use std::collections::HashSet;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

mod key;
pub mod resolver;
pub(crate) mod universal_resolver;
mod web;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "VerificationRelationshipType")]
    pub type VerificationRelationshipType;

    #[wasm_bindgen(typescript_type = "DIDDocument")]
    pub type DIDDocument;

    #[wasm_bindgen(typescript_type = "DIDVerificationMethod")]
    pub type DIDVerificationMethod;

    #[wasm_bindgen(typescript_type = "DIDResolution")]
    pub type DIDResolution;

    #[wasm_bindgen(typescript_type = "ResolutionOptions")]
    pub type ResolutionOptions;
}

impl TryFrom<DIDResolution> for ResolutionOutput {
    type Error = JsError;

    fn try_from(value: DIDResolution) -> Result<Self, Self::Error> {
        let js_value = value.into();

        let document = utils::get_property(&js_value, "document").and_then(|value| {
            serde_wasm_bindgen::from_value(value.into()).map_err(JsError::from)
        })?;

        let js_metadata = utils::get_property(&js_value, "metadata")?;
        let js_content_type = utils::get_property(&js_metadata, "contentType")?;

        let content_type = if js_content_type.is_null() || js_content_type.is_undefined() {
            None
        } else {
            Some(utils::js_value_to_string(js_content_type))
        };

        let metadata = agent_sdk::did::ResolutionMetadata::from_content_type(content_type);

        let document_metadata =
            utils::get_property(&js_value, "document_metadata").and_then(|value| {
                serde_wasm_bindgen::from_value(value.into()).map_err(JsError::from)
            })?;

        Ok(ResolutionOutput::new(document, document_metadata, metadata))
    }
}

impl TryFrom<ResolutionOutput> for DIDResolution {
    type Error = JsError;

    fn try_from(value: ResolutionOutput) -> Result<Self, Self::Error> {
        let json_value = serde_json::json!({
            "document": value.document,
            "metadata": value.metadata,
            "document_metadata": value.document_metadata,
        });

        utils::convert_to_opaque_object_unchecked(json_value)
    }
}

/// Verification method key used in the DID Document
#[wasm_bindgen]
pub struct VerificationMethodKey {
    key: JsKeyHandle,
    verification_relationships: HashSet<agent_sdk::did::VerificationRelationshipType>,
}

#[wasm_bindgen]
impl VerificationMethodKey {
    /// Creates a new `VerificationMethodKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - a key to include in DID document.
    /// * `verification_relationships` - A vector of verification relationship types.
    #[wasm_bindgen(constructor)]
    pub fn new(
        key: KeyHandle,
        verification_relationships: Vec<VerificationRelationshipType>,
    ) -> Result<Self, JsError> {
        let verification_relationships = verification_relationships
            .into_iter()
            .map(utils::convert_to_rust_object)
            .collect::<Result<HashSet<_>, _>>()?;

        Ok(Self {
            key: JsKeyHandle::new(key),
            verification_relationships,
        })
    }
}
