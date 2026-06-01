// Re-export std `core::ops` so that wasm_bindgen's generated `core::ops` paths
// (where `core` resolves to this module) remain valid.
pub use ::core::ops;

use crate::utils;
use wasm_bindgen::JsError;

pub mod signer;
pub mod types;

mod holder;
mod issuer;
mod status_issuer;
mod verifier;

pub use holder::VcCoreHolder;
pub use issuer::VcCoreIssuer;
pub use status_issuer::VcCoreStatusIssuer;
pub use verifier::VcCoreVerifier;

pub(super) fn decode_holder_binder(
    v: Option<HolderBinder>,
) -> Result<Option<agent_sdk::vc::core::HolderBinder>, JsError> {
    v.map(|b| utils::convert_to_rust_object::<_, types::WasmHolderBinder>(b).map(Into::into))
        .transpose()
}

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    // Metadata inputs — `Js`-prefixed to avoid collisions with SDK types imported in each module.
    #[wasm_bindgen(typescript_type = "IssuerMetadata")]
    pub type JsIssuerMetadata;

    #[wasm_bindgen(typescript_type = "HolderMetadata")]
    pub type JsHolderMetadata;

    #[wasm_bindgen(typescript_type = "StatusIssuerMetadata")]
    pub type JsStatusIssuerMetadata;

    // Non-conflicting VC core types.
    #[wasm_bindgen(typescript_type = "CredentialRequest")]
    pub type CredentialRequest;

    #[wasm_bindgen(typescript_type = "CredentialOfferData")]
    pub type CredentialOfferData;

    #[wasm_bindgen(typescript_type = "CredentialStatusInfo")]
    pub type CredentialStatusInfo;

    #[wasm_bindgen(typescript_type = "VCStatusesData")]
    pub type VCStatusesData;

    #[wasm_bindgen(typescript_type = "StatusList")]
    pub type StatusList;

    #[wasm_bindgen(typescript_type = "HolderBinder")]
    pub type HolderBinder;

    #[wasm_bindgen(typescript_type = "PresentationInput")]
    pub type PresentationInput;

    #[wasm_bindgen(typescript_type = "Presentation")]
    pub type Presentation;

    #[wasm_bindgen(typescript_type = "VCStatus")]
    pub type VCStatus;

    #[wasm_bindgen(typescript_type = "UnsignedCredential")]
    pub type WasmUnsignedCredential;
}
