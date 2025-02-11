use crate::kms::{JsKms, NativeKms, UnifiedKms};
use crate::vc::core::JsStatusIssuerMetadata;
use crate::vc::core::{JsStatusList, JsVCStatusesData};
use agent_sdk::vc::core::{status_issuer::StatusIssuerService, StatusIssuer, StatusIssuerMetadata};
use napi::{Either, Error};
use napi_derive::napi;

#[napi]
pub struct VCCoreStatusIssuer(pub(crate) Box<dyn StatusIssuer>);

#[napi]
impl VCCoreStatusIssuer {
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
