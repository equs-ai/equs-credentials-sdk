use crate::error::IntoNapiError;
use crate::http::ReqwestHttpClient;
use crate::utils::to_json_object;
use crate::vc::JsonObject;
use agent_sdk::reqwest::ReqwestClient;
use agent_sdk::vc::oid4vci::{
    AuthorizationMetadata, IssuerMetadata, MetadataDiscovery as AsdkMetadataDiscovery,
};
use napi_derive::napi;

#[napi]
pub struct MetadataDiscovery {
    http_client: ReqwestClient,
}

#[napi]
impl MetadataDiscovery {
    #[napi(constructor)]
    pub fn new(http_client: &ReqwestHttpClient) -> Self {
        Self {
            http_client: http_client.inner(),
        }
    }

    #[napi(ts_return_type = "Promise<OID4VCIIssuerMetadata>")]
    pub async fn discover_issuer_metadata(
        &self,
        issuer_url: String,
    ) -> Result<JsonObject, napi::Error> {
        let metadata: IssuerMetadata =
            AsdkMetadataDiscovery::discover_metadata(&self.http_client, &issuer_url)
                .await
                .map_err(IntoNapiError::into_napi_error)?;

        to_json_object(metadata)
    }

    #[napi(ts_return_type = "Promise<OID4VCIIssuerMetadata>")]
    pub async fn discover_auth_server_metadata(
        &self,
        auth_server_url: String,
    ) -> Result<JsonObject, napi::Error> {
        let metadata: AuthorizationMetadata =
            AsdkMetadataDiscovery::discover_metadata(&self.http_client, &auth_server_url)
                .await
                .map_err(IntoNapiError::into_napi_error)?;

        to_json_object(metadata)
    }
}
