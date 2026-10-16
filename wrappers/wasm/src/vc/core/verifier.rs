use super::{HolderBinder, Presentation, VCStatus};
use crate::did::UniversalDIDResolver;
use crate::http::ReqwestHttpClient;
use crate::utils;
use crate::utils::Claims;
use crate::vc::core::types::{WasmPresentation, WasmVCStatus};
use equs_sdk::vc::core::{Verifier, VerifierService as CoreVerifierService};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

/// A low-level protocol-agnostic `Verifier` API.
///
/// Provides methods for verifying verifiable presentations and obtaining credential status.
#[wasm_bindgen]
pub struct VcCoreVerifier(Box<dyn Verifier>);

#[wasm_bindgen]
impl VcCoreVerifier {
    /// Creates a new `VCCoreVerifier`.
    ///
    /// @param {string} verifierId - identifier for this verifier (used as `aud`).
    /// @param {UniversalDIDResolver} didResolver - DID resolver used during verification.
    #[wasm_bindgen(constructor)]
    pub fn new(verifier_id: String, did_resolver: &UniversalDIDResolver) -> Self {
        let verifier_service = CoreVerifierService::new(&verifier_id, did_resolver.0.clone());
        VcCoreVerifier(Box::new(verifier_service))
    }

    /// Verifies a presentation and returns the verified claims.
    ///
    /// @param {HolderBinder} [holderBinder] - optional holder binding (nonce + verifier ID).
    /// @param {Presentation} presentation - the presentation to verify.
    /// @param {ReqwestHttpClient} httpClient - HTTP client for status-list lookups.
    /// @returns {Promise<Claims>}
    #[wasm_bindgen(js_name = verifyPresentation)]
    pub async fn verify_presentation(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation: Presentation,
        http_client: &ReqwestHttpClient,
    ) -> Result<Claims, JsError> {
        let holder_binder = super::decode_holder_binder(holder_binder)?;

        let wasm_pres: WasmPresentation = utils::convert_to_rust_object(presentation)?;
        let equs_sdk_pres = wasm_pres.try_into()?;

        let claims = self
            .0
            .verify_presentation(holder_binder, &equs_sdk_pres, &http_client.inner())
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let claims_value: serde_json::Value = claims
            .try_into()
            .map_err(|e: equs_sdk::vc::claims::Error| JsError::new(&e.to_string()))?;
        utils::convert_to_opaque_object_unchecked(claims_value)
    }

    /// Obtains the credential status from a presentation.
    ///
    /// @param {Presentation} presentation - presentation containing the VC with status.
    /// @param {ReqwestHttpClient} httpClient - HTTP client for status-list lookups.
    /// @returns {Promise<VCStatus | null>}
    #[wasm_bindgen(js_name = obtainCredentialStatus)]
    pub async fn obtain_credential_status(
        &self,
        presentation: Presentation,
        http_client: &ReqwestHttpClient,
    ) -> Result<Option<VCStatus>, JsError> {
        let wasm_pres: WasmPresentation = utils::convert_to_rust_object(presentation)?;
        let equs_sdk_pres = wasm_pres.try_into()?;

        let status = self
            .0
            .obtain_credential_status(&equs_sdk_pres, &http_client.inner())
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        status
            .map(|s| -> Result<VCStatus, JsError> {
                let wasm_status: WasmVCStatus = s.try_into()?;
                utils::convert_to_opaque_object_unchecked(wasm_status)
            })
            .transpose()
    }
}
