use crate::utils::to_json_object;
use crate::vc::JsonObject;
#[cfg(debug_assertions)]
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::vc::oid4vci::CredentialOfferResolver;
use napi::{Error, Result};
use napi_derive::napi;
use url::Url;

#[napi]
pub struct OID4VCICredentialOfferResolver(
    CredentialOfferResolver<agent_sdk::reqwest::ReqwestClient>,
);

#[napi]
#[allow(unused)]
impl OID4VCICredentialOfferResolver {
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        let mut inner_resolver = CredentialOfferResolver::new()
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        #[cfg(debug_assertions)]
        {
            inner_resolver = CredentialOfferResolver::with_http_client(
                ReqwestClientBuilder::new()
                    .insecure()
                    .build()
                    .map_err(|err| Error::from_reason(format!("{:?}", err)))?,
            )
        }

        let resolver = OID4VCICredentialOfferResolver(inner_resolver);

        Ok(resolver)
    }

    #[napi(ts_return_type = "Promise<CredentialOfferParameters>")]
    pub async fn resolve(&self, offer_uri: String) -> Result<JsonObject> {
        let offer_uri = Url::parse(&offer_uri).map_err(|e| Error::from_reason(e.to_string()))?;
        self.0
            .resolve(offer_uri)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))
            .and_then(to_json_object)
    }
}
