use crate::http::ReqwestHttpClient;
use crate::utils::to_json_object;
use crate::vc::JsonObject;
use equs_sdk::did::universal::DIDResolver as EqusSdkDIDResolver;
use equs_sdk::did::webvh::client::DIDWebVh;
use equs_sdk::did::{ResolutionOptions, SpruceDID};
use napi::{Error, Result};
use napi_derive::napi;
use std::sync::Arc;

#[napi(js_name = "DIDWebVh")]
pub struct JsDIDWebVh {
    pub(crate) inner: DIDWebVh,
}

#[napi]
impl JsDIDWebVh {
    #[napi(constructor)]
    pub fn new(http_client: &ReqwestHttpClient) -> Self {
        Self {
            inner: DIDWebVh::new(Arc::new(http_client.inner())),
        }
    }

    #[napi(getter)]
    pub fn method_name(&self) -> String {
        self.inner.method_name()
    }

    #[napi(ts_return_type = "Promise<DIDResolution>")]
    pub async fn resolve_representation(
        &self,
        did: String,
        #[napi(ts_arg_type = "ResolutionOptions")] _options: JsonObject,
    ) -> Result<JsonObject> {
        let ssi_did =
            SpruceDID::new(&did).map_err(|e| Error::from_reason(format!("Invalid DID: {e}")))?;

        let output = self
            .inner
            .resolve_representation(ssi_did, ResolutionOptions::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        to_json_object(serde_json::json!({
            "document": output.document,
            "document_metadata": {
                "deactivated": output.document_metadata.deactivated,
            },
            "metadata": {
                "contentType": output.metadata.content_type,
            },
        }))
    }
}
