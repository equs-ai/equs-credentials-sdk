mod key;
mod web;

use crate::utils::to_json_object;
use crate::vc::JsonObject;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver as ASDKDIDResolver};
use napi::{Error, Result};
use napi_derive::napi;
use std::str::FromStr;

#[napi]
pub struct NativeDIDResolver(UniversalResolver);

#[napi]
impl NativeDIDResolver {
    #[napi(ts_return_type = "Promise<DIDVerificationMethod>")]
    pub async fn resolve_verification_method(&self, did: String) -> Result<JsonObject> {
        self.0
            .resolve_into_any_verification_method(
                &DIDBuf::from_str(&did).map_err(|err| Error::from_reason(err.to_string()))?,
            )
            .await
            .map_err(|err| Error::from_reason(err.to_string()))
            .and_then(to_json_object)
    }

    #[napi(ts_return_type = "Promise<DIDResolution>")]
    pub async fn resolve(&self, did: String) -> Result<JsonObject> {
        self.0
            .resolve(&DIDBuf::from_str(&did).map_err(|err| Error::from_reason(err.to_string()))?)
            .await
            .map_err(|err| Error::from_reason(err.to_string()))
            .map(|output| {
                serde_json::json!({
                    "document": output.document,
                    "metadata": output.metadata,
                    "document_metadata": output.document_metadata,
                })
            })
            .and_then(to_json_object)
    }
}

#[allow(unused)]
#[napi]
pub fn create_universal_did_resolver() -> NativeDIDResolver {
    let resolver = UniversalResolver::default();

    NativeDIDResolver(resolver)
}
