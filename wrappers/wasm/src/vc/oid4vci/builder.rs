use crate::http::HttpClient;
use crate::kms::{JsKeyHandle, JsKms, Kms};
use crate::utils;
use crate::vault::{JsVault, Vault};
use crate::vc::oid4vci::holder::OID4VCIHolder;
use crate::vc::oid4vci::{OID4VCICredentialOffer, OID4VCIIssuerMetadata};
use agent_sdk::vc::oid4vci::HolderBuilder;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};

/// A type containing options of discovery of the `Issuer` for a `Holder`.
#[wasm_bindgen]
pub struct IssuerDiscovery(agent_sdk::vc::oid4vci::IssuerDiscovery);

#[wasm_bindgen]
impl IssuerDiscovery {
    /// Creates an `IssuerDiscovery` instance using an Issuer URL.
    #[wasm_bindgen(js_name = fromUrl)]
    pub fn from_url(url: String) -> Self {
        IssuerDiscovery(agent_sdk::vc::oid4vci::IssuerDiscovery::Url(url))
    }

    /// Creates an `IssuerDiscovery` instance from a credential offer.
    #[wasm_bindgen(js_name = fromOffer)]
    pub fn from_offer(credential_offer: OID4VCICredentialOffer) -> Result<Self, JsError> {
        let credential_offer = utils::convert_to_rust_object(credential_offer)?;

        Ok(IssuerDiscovery(
            agent_sdk::vc::oid4vci::IssuerDiscovery::Offer(credential_offer),
        ))
    }

    /// Creates an `IssuerDiscovery` instance from issuer metadata and authentication metadata.
    #[wasm_bindgen(js_name = "fromMetadata")]
    pub fn from_metadata(
        issuer_metadata: OID4VCIIssuerMetadata,
        auth_metadata: JsValue,
    ) -> Result<Self, JsError> {
        let credential_offer = utils::convert_to_rust_object(issuer_metadata)?;
        let auth_metadata = utils::convert_to_rust_object(auth_metadata)?;

        Ok(IssuerDiscovery(
            agent_sdk::vc::oid4vci::IssuerDiscovery::Metadata(credential_offer, auth_metadata),
        ))
    }
}

impl IssuerDiscovery {
    pub fn inner(&self) -> agent_sdk::vc::oid4vci::IssuerDiscovery {
        self.0.clone()
    }
}

/// A builder for instantiating `oid4vci` `Holder`.
#[wasm_bindgen]
pub struct OID4VCIHolderBuilder(
    HolderBuilder<JsKeyHandle, JsKms, JsVault, agent_sdk::reqwest::ReqwestClient>,
);

#[wasm_bindgen]
impl OID4VCIHolderBuilder {
    /// Creates a new `Builder` initialized with defaults.
    ///
    /// # Arguments
    ///
    /// * `kms` - an inner [Kms].
    /// * `vault` - an inner [Vault].
    /// * `client_id` - a client ID.
    /// * `iss_discovery` - a data to discover the `Issuer`.
    ///   Either `CredentialOffer`, `IssuerMetadata` and `AuthorizationMetadata` or `Issuer` url.
    #[wasm_bindgen(constructor)]
    pub fn new(
        kms: Kms,
        vault: Vault,
        client_id: String,
        issuer_discovery: &IssuerDiscovery,
    ) -> Self {
        let builder = HolderBuilder::new(
            JsKms::new(kms),
            JsVault::new(vault),
            client_id,
            issuer_discovery.inner(),
        );

        OID4VCIHolderBuilder(builder)
    }

    /// Use a specific `RedirectUrl`.
    ///
    /// # Arguments
    ///
    /// * `redirect_url` - an Oauth2 Redirect Url used by authorization endpoint.
    #[wasm_bindgen(js_name = withRedirectUrl)]
    pub fn with_redirect_url(self, redirect_url: String) -> Self {
        OID4VCIHolderBuilder(self.0.with_redirect_url(redirect_url))
    }

    /// Use a specific `HttpClient`.
    ///
    /// # Arguments
    ///
    /// * `http_client` - a http client.
    #[wasm_bindgen(js_name = withHttpClient)]
    pub fn with_http_client(self, client: &HttpClient) -> Self {
        OID4VCIHolderBuilder(self.0.with_http_client(client.inner()))
    }

    /// Builds a `Holder`.
    ///
    /// # Returns
    ///
    /// A `Holder` API on success.
    pub async fn build(self) -> Result<OID4VCIHolder, JsError> {
        let holder = self
            .0
            .build()
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        Ok(OID4VCIHolder::from_holder(holder))
    }
}
