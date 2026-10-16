use crate::http::ReqwestHttpClient;
use crate::utils;
use crate::vc::oid4vci::OID4VCIIssuerMetadata;
use equs_sdk::reqwest::ReqwestClient;
use equs_sdk::vc::oid4vci::{
    AuthorizationMetadata, IssuerMetadata, MetadataDiscovery as EqusSdkMetadataDiscovery,
};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};

#[wasm_bindgen]
pub struct MetadataDiscovery {
    http_client: ReqwestClient,
}

#[wasm_bindgen]
impl MetadataDiscovery {
    #[wasm_bindgen(constructor)]
    pub fn new(http_client: ReqwestHttpClient) -> Self {
        Self {
            http_client: http_client.inner(),
        }
    }

    #[wasm_bindgen(js_name = "discoverIssuerMetadata")]
    pub async fn discover_issuer_metadata(
        &self,
        issuer_url: String,
    ) -> Result<OID4VCIIssuerMetadata, JsError> {
        let metadata: IssuerMetadata =
            EqusSdkMetadataDiscovery::discover_metadata(&self.http_client, &issuer_url)
                .await
                .map_err(|e| JsError::new(e.to_string().as_str()))?;

        utils::convert_to_opaque_object_unchecked(metadata)
    }

    #[wasm_bindgen(js_name = "discoverAuthServerMetadata")]
    pub async fn discover_auth_server_metadata(
        &self,
        auth_server_url: String,
    ) -> Result<JsValue, JsError> {
        let metadata: AuthorizationMetadata =
            EqusSdkMetadataDiscovery::discover_metadata(&self.http_client, &auth_server_url)
                .await
                .map_err(|e| JsError::new(e.to_string().as_str()))?;

        utils::convert_to_opaque_object_unchecked(metadata)
    }
}
