use crate::inmem::kms::InMemKeyHandle;
use crate::utils;
use std::collections::HashSet;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

mod key;
mod universal_resolver;
mod web;

/// Verification method key used in the DID Document
#[wasm_bindgen]
pub struct VerificationMethodKey {
    key: agent_sdk::inmem::kms::KeyHandle,
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
        key: &InMemKeyHandle,
        verification_relationships: Vec<VerificationRelationshipType>,
    ) -> Result<Self, JsError> {
        let verification_relationships = verification_relationships
            .into_iter()
            .map(utils::convert_to_rust_object)
            .collect::<Result<HashSet<_>, _>>()?;

        Ok(Self {
            key: key.inner().clone(),
            verification_relationships,
        })
    }
}

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
}
