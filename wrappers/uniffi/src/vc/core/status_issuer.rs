use crate::common::Result;
use crate::kms::{Kms, WrappedKms};
use crate::vc::core::types::{StatusIssuerMetadata, VCStatusesData};
use equs_sdk::vc::StatusList;
use equs_sdk::vc::core::StatusIssuer;
use equs_sdk::vc::core::status_issuer::StatusIssuerService;
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct VCCoreStatusIssuer(pub(crate) Box<dyn StatusIssuer>);

#[uniffi::export]
impl VCCoreStatusIssuer {
    #[uniffi::constructor]
    pub fn new(kms: Arc<dyn Kms>, metadata: StatusIssuerMetadata) -> Result<Self> {
        let metadata = metadata.try_into()?;
        let service = StatusIssuerService::new(WrappedKms::new(kms), metadata);
        Ok(Self(Box::new(service)))
    }
}

#[derive(uniffi::Object)]
pub struct OID4VCIStatusIssuerBuilder {
    kms: Arc<dyn Kms>,
    metadata: StatusIssuerMetadata,
}

#[uniffi::export]
impl OID4VCIStatusIssuerBuilder {
    #[uniffi::constructor]
    pub fn new(kms: Arc<dyn Kms>, metadata: StatusIssuerMetadata) -> Self {
        Self { kms, metadata }
    }

    pub fn build(&self) -> Result<VCCoreStatusIssuer> {
        VCCoreStatusIssuer::new(self.kms.clone(), self.metadata.clone())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VCCoreStatusIssuer {
    pub async fn issue_status_list(
        &self,
        status_list_id: String,
        statuses: VCStatusesData,
    ) -> Result<StatusList> {
        let vc_statuses = statuses.try_into()?;
        Ok(self
            .0
            .issue_status_list(&status_list_id, vc_statuses)
            .await?)
    }
}
