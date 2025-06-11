use crate::http::ReqwestHttpClient;
use crate::utils::convert_to_opaque_object_unchecked;
use crate::vc::oid4vci::OID4VCICredentialOffer;
use agent_sdk::vc::oid4vci::CredentialOfferResolver;
use url::Url;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

/// A Credential Offer resolver.
///
/// Resolves `OID4VCICredentialOffer` instances from a given Credential Offer URI.
#[wasm_bindgen]
pub struct OID4VCICredentialOfferResolver(
    CredentialOfferResolver<agent_sdk::reqwest::ReqwestClient>,
);

#[wasm_bindgen]
impl OID4VCICredentialOfferResolver {
    /// Creates a new Credential Offer resolver.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Self, JsError> {
        let resolver = CredentialOfferResolver::new().map_err(JsError::from)?;

        Ok(OID4VCICredentialOfferResolver(resolver))
    }

    /// Returns a new [CredentialOfferResolver] to resolve credential offer params [OID4VCICredentialOffer]
    /// by using a specific [ReqwestHttpClient].
    ///
    /// # Arguments
    ///
    /// * `http_client` - a custom http client.
    ///
    /// # Returns
    ///
    /// A new credential offer resolver.
    #[wasm_bindgen(js_name = withHttpClient)]
    pub fn with_http_client(http_client: ReqwestHttpClient) -> Self {
        let resolver = CredentialOfferResolver::with_http_client(http_client.inner());

        OID4VCICredentialOfferResolver(resolver)
    }

    /// Resolves the [OID4VCICredentialOffer] from the credential offer uri
    ///
    /// # Arguments
    ///
    /// * `offer_uri` - offer uri obtained from the credential issuer.
    ///
    /// # Returns
    ///
    /// A resolved credential offer params [CredentialOfferParams].
    ///
    /// # Errors
    ///
    /// * Returns an error when resolution of credential offer fails.
    pub async fn resolve(&self, offer_uri: String) -> Result<OID4VCICredentialOffer, JsError> {
        let offer_uri = Url::parse(&offer_uri).map_err(JsError::from)?;

        self.0
            .resolve(offer_uri)
            .await
            .map_err(|err| JsError::new(&format!("{err:?}")))
            .and_then(convert_to_opaque_object_unchecked)
    }
}
