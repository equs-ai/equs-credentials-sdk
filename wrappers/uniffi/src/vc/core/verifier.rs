use crate::common::{Error, JsonValue, Result};
use crate::did::universal_resolver::UniversalDIDResolver;
use crate::http::{HttpClient, WrappedHttpClient};
use crate::vc::VCStatus;
use crate::vc::core::types::HolderBinder;
use equs_sdk::vc::Presentation;
use equs_sdk::vc::core::{Verifier, VerifierService};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct VCCoreVerifier {
    inner: Box<dyn Verifier>,
    http_client: Arc<WrappedHttpClient>,
}

#[uniffi::export]
impl VCCoreVerifier {
    #[uniffi::constructor]
    pub fn new(
        verifier_id: String,
        did_resolver: Arc<UniversalDIDResolver>,
        http_client: Arc<dyn HttpClient>,
    ) -> Self {
        let service = VerifierService::new(&verifier_id, did_resolver.inner().clone());
        Self {
            inner: Box::new(service),
            http_client: Arc::new(WrappedHttpClient::new(http_client)),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl VCCoreVerifier {
    pub async fn verify_presentation(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation: Presentation,
    ) -> Result<JsonValue> {
        let claims = self
            .inner
            .verify_presentation(holder_binder, &presentation, self.http_client.as_ref())
            .await?;
        serde_json::to_value(&claims).map_err(|e| Error::Core(e.to_string()))
    }

    pub async fn obtain_credential_status(
        &self,
        presentation: Presentation,
    ) -> Result<Option<VCStatus>> {
        Ok(self
            .inner
            .obtain_credential_status(&presentation, self.http_client.as_ref())
            .await?)
    }
}
