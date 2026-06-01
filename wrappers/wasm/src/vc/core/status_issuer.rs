use super::{JsStatusIssuerMetadata, StatusList, VCStatusesData};
use crate::kms::{JsKms, Kms};
use crate::utils;
use crate::vc::core::types::{WasmStatusIssuerMetadata, WasmStatusList, WasmVCStatusesData};
use agent_sdk::vc::core::{StatusIssuer, StatusIssuerMetadata, status_issuer::StatusIssuerService};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

/// A status-list issuer.
///
/// Provides a method for issuing VC status lists.
#[wasm_bindgen]
pub struct VcCoreStatusIssuer(Box<dyn StatusIssuer>);

#[wasm_bindgen]
impl VcCoreStatusIssuer {
    /// Creates a new `VCCoreStatusIssuer`.
    ///
    /// @param {Kms} kms - the key-management service backing status-list signing.
    /// @param {StatusIssuerMetadata} metadata - status issuer configuration.
    #[wasm_bindgen(constructor)]
    pub fn new(kms: Kms, metadata: JsStatusIssuerMetadata) -> Result<Self, JsError> {
        let wasm_meta: WasmStatusIssuerMetadata = utils::convert_to_rust_object(metadata)?;
        let metadata: StatusIssuerMetadata = wasm_meta.try_into()?;
        let issuer_service = StatusIssuerService::new(JsKms::new(kms), metadata);
        Ok(VcCoreStatusIssuer(Box::new(issuer_service)))
    }

    /// Issues a new status list for a given status list identifier and credential statuses.
    ///
    /// @param {string} statusListId - unique identifier of the status list definition.
    /// @param {VCStatusesData} statuses - credential statuses data.
    /// @returns {Promise<StatusList>}
    #[wasm_bindgen(js_name = issueStatusList)]
    pub async fn issue_status_list(
        &self,
        status_list_id: String,
        statuses: VCStatusesData,
    ) -> Result<StatusList, JsError> {
        let wasm_statuses: WasmVCStatusesData = utils::convert_to_rust_object(statuses)?;
        let vc_statuses = wasm_statuses.try_into()?;

        let status_list = self
            .0
            .issue_status_list(status_list_id.as_str(), vc_statuses)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let wasm_list: WasmStatusList = status_list.try_into()?;
        utils::convert_to_opaque_object_unchecked(wasm_list)
    }
}
