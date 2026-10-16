use crate::error::IntoNapiError;
use crate::http::ReqwestHttpClient;
use crate::utils::to_json_object;
use crate::vc::JsonObject;
use equs_sdk::vc::oid4vci::CredentialOfferResolver;
use napi::{Error, Result};
use napi_derive::napi;
use url::Url;

/// @property resolve - {@link OID4VCICredentialOfferResolver.resolve}

#[napi(js_name = "OID4VCICredentialOfferResolver")]
pub struct OID4VCICredentialOfferResolver(
    CredentialOfferResolver<equs_sdk::reqwest::ReqwestClient>,
);

#[napi]
#[allow(unused)]
impl OID4VCICredentialOfferResolver {
    /// Returns a new {@link OID4VCICredentialOfferResolver} to resolve {@link OID4VCICredentialOffer}
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        let mut inner_resolver =
            CredentialOfferResolver::new().map_err(IntoNapiError::into_napi_error)?;

        let resolver = OID4VCICredentialOfferResolver(inner_resolver);

        Ok(resolver)
    }

    /// Returns a new {@link OID4VCICredentialOfferResolver} to resolve credential offer params {@link OID4VCICredentialOffer}
    /// by using a specific {@link ReqwestHttpClient}.
    ///
    /// @param {ReqwestHttpClient} httpClient - Reqwest Http client
    ///
    /// @returns {OID4VCICredentialOfferResolver}
    #[napi(factory, ts_return_type = "OID4VCICredentialOfferResolver")]
    pub fn with_http_client(
        http_client: &ReqwestHttpClient,
    ) -> Result<OID4VCICredentialOfferResolver> {
        let resolver = CredentialOfferResolver::with_http_client(http_client.inner());

        Ok(OID4VCICredentialOfferResolver(resolver))
    }

    /// Resolves the {@link OID4VCICredentialOffer} from the credential offer uri
    ///
    /// @param {string} offerUri - offer uri obtained from the credential issuer.
    ///
    /// @returns {OID4VCICredentialOffer} - A resolved credential offer params {@link OID4VCICredentialOffer}.
    #[napi(ts_return_type = "Promise<OID4VCICredentialOffer>")]
    pub async fn resolve(&self, offer_uri: String) -> Result<JsonObject> {
        let offer_uri = Url::parse(&offer_uri).map_err(|e| Error::from_reason(e.to_string()))?;
        self.0
            .resolve(offer_uri)
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(to_json_object)
    }
}
