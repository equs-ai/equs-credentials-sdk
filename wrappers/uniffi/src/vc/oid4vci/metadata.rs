use crate::common::{Error, JsonValue};
use crate::http::{HttpClient, WrappedHttpClient};
use equs_sdk::vc::oid4vci::{
    AuthorizationMetadata, IssuerMetadata, MetadataDiscovery as EqusSdkMetadataDiscovery,
};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct MetadataDiscovery {
    http_client: WrappedHttpClient,
}

#[uniffi::export(async_runtime = "tokio")]
impl MetadataDiscovery {
    #[uniffi::constructor]
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        Self {
            http_client: WrappedHttpClient::new(http_client),
        }
    }

    #[uniffi::method]
    pub async fn discover_issuer_metadata(
        &self,
        issuer_url: String,
    ) -> crate::common::Result<JsonValue> {
        let metadata: IssuerMetadata =
            EqusSdkMetadataDiscovery::discover_metadata(&self.http_client, &issuer_url)
                .await
                .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))?;

        serde_json::to_value(metadata).map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
    }

    #[uniffi::method]
    pub async fn discover_auth_server_metadata(
        &self,
        server_url: String,
    ) -> crate::common::Result<JsonValue> {
        let metadata: AuthorizationMetadata =
            EqusSdkMetadataDiscovery::discover_metadata(&self.http_client, &server_url)
                .await
                .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))?;

        serde_json::to_value(metadata).map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
    }
}
