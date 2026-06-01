use crate::error::IntoNapiError;
use crate::kms::JsKms;
use crate::vc::core::JsStatusIssuerMetadata;
use crate::vc::core::{JsStatusList, JsVCStatusesData};
use agent_sdk::vc::core::{StatusIssuer, StatusIssuerMetadata, status_issuer::StatusIssuerService};
use napi::Error;
use napi_derive::napi;

/// Status lists Issuer.
///
/// Provides method for issuing VC status lists
///
/// @property issueStatusList - {@link VCCoreStatusIssuer.issueStatusList}
#[napi(js_name = "_VcCoreStatusIssuer")]
pub struct VCCoreStatusIssuer(pub(crate) Box<dyn StatusIssuer>);

#[napi]
impl VCCoreStatusIssuer {
    /// Build a new `VCCoreStatusIssuer`.
    ///
    /// @param {Kms} kms - the key-management service backing status-list signing.
    /// @param {StatusIssuerMetadata} metadata - status issuer configuration.
    #[napi(constructor)]
    pub fn new(kms: JsKms, metadata: JsStatusIssuerMetadata) -> Result<Self, Error> {
        let metadata: StatusIssuerMetadata = metadata.try_into()?;
        let issuer_service = StatusIssuerService::new(kms, metadata);
        Ok(Self(Box::new(issuer_service)))
    }

    /// Issues a new status list for a given status list identifier and a set of credential statuses.
    ///
    /// @param {string} statusListId - a unique identifier of the status list definition.
    /// @param {VCStatusesData} statuses - credential statuses data.
    ///
    /// @returns {StatusList} - The issued {@link StatusList} if successful.
    #[napi]
    pub async fn issue_status_list(
        &self,
        status_list_id: String,
        statuses: JsVCStatusesData,
    ) -> Result<JsStatusList, Error> {
        let vc_statuses = statuses.try_into()?;

        self.0
            .issue_status_list(status_list_id.as_str(), vc_statuses)
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(|v| v.try_into())
    }
}

// TODO(next-release): remove `create_status_issuer` — superseded by `new VcCoreStatusIssuer(...)`.
/// @deprecated Use `new VcCoreStatusIssuer(kms, metadata)` instead.
/// This factory will be removed in the next release.
#[allow(unused)]
#[napi]
pub fn create_status_issuer(
    kms: JsKms,
    metadata: JsStatusIssuerMetadata,
) -> Result<VCCoreStatusIssuer, Error> {
    tracing::warn!(
        "`createStatusIssuer` is deprecated and will be removed in the next release. \
         Use `new VcCoreStatusIssuer(kms, metadata)` instead."
    );
    VCCoreStatusIssuer::new(kms, metadata)
}
