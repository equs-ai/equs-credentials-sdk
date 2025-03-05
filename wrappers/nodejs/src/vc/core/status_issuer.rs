use crate::kms::{JsKms, NativeKms, UnifiedKms};
use crate::vc::core::JsStatusIssuerMetadata;
use crate::vc::core::{JsStatusList, JsVCStatusesData};
use agent_sdk::vc::core::{status_issuer::StatusIssuerService, StatusIssuer, StatusIssuerMetadata};
use napi::{Either, Error};
use napi_derive::napi;

/// Status lists Issuer.
///
/// Provides method for issuing VC status lists
///
/// @property issueStatusList - {@link VCCoreStatusIssuer.issueStatusList}
#[napi]
pub struct VCCoreStatusIssuer(pub(crate) Box<dyn StatusIssuer>);

#[napi]
impl VCCoreStatusIssuer {
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
            .map_err(|e| Error::from_reason(e.to_string()))
            .and_then(|v| v.try_into())
    }
}

#[allow(unused)]
#[napi]
pub fn create_status_issuer(
    kms: Either<&NativeKms, JsKms>,
    metadata: JsStatusIssuerMetadata,
) -> Result<VCCoreStatusIssuer, Error> {
    let kms: UnifiedKms = kms.into();
    let metadata: StatusIssuerMetadata = metadata.try_into()?;
    let issuer_service = StatusIssuerService::new(kms, metadata);

    Ok(VCCoreStatusIssuer(Box::new(issuer_service)))
}
