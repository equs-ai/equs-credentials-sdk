use crate::did::resolver::{DIDResolver, JsDIDResolver};
use crate::http::ReqwestHttpClient;
use crate::kms::{JsKeyHandle, JsKms, Kms};
use crate::utils;
use crate::vault::{JsVault, Vault};
use crate::vc::core::types::WasmProofOfPossessionNotBefore;
use crate::vc::oid4vci::holder::CredentialExtraVerification;
use crate::vc::oid4vci::holder::OID4VCIHolder;
use crate::vc::oid4vci::{OID4VCICredentialOffer, OID4VCIIssuerMetadata};
use equs_sdk::Duration;
use equs_sdk::vc::oid4vci::HolderBuilder;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};

/// A type containing options of discovery of the `Issuer` for a `Holder`.
#[wasm_bindgen]
pub struct IssuerDiscovery(equs_sdk::vc::oid4vci::IssuerDiscovery);

#[wasm_bindgen]
impl IssuerDiscovery {
    /// Creates an `IssuerDiscovery` instance using an Issuer URL.
    #[wasm_bindgen(js_name = fromUrl)]
    pub fn from_url(url: String) -> Self {
        IssuerDiscovery(equs_sdk::vc::oid4vci::IssuerDiscovery::Url(url))
    }

    /// Creates an `IssuerDiscovery` instance from a credential offer.
    #[wasm_bindgen(js_name = fromOffer)]
    pub fn from_offer(credential_offer: OID4VCICredentialOffer) -> Result<Self, JsError> {
        let credential_offer = utils::convert_to_rust_object(credential_offer)?;

        Ok(IssuerDiscovery(
            equs_sdk::vc::oid4vci::IssuerDiscovery::Offer(credential_offer),
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
            equs_sdk::vc::oid4vci::IssuerDiscovery::Metadata(credential_offer, auth_metadata),
        ))
    }
}

impl IssuerDiscovery {
    pub fn inner(&self) -> equs_sdk::vc::oid4vci::IssuerDiscovery {
        self.0.clone()
    }
}

/// A builder for instantiating `oid4vci` `Holder`.
#[wasm_bindgen]
pub struct OID4VCIHolderBuilder(
    HolderBuilder<JsKeyHandle, JsKms, JsVault, equs_sdk::reqwest::ReqwestClient>,
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
        http_client: &ReqwestHttpClient,
    ) -> Self {
        let builder = HolderBuilder::new(
            JsKms::new(kms),
            JsVault::new(vault),
            client_id,
            issuer_discovery.inner(),
            http_client.inner(),
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

    /// Use a specific `did_resolver`.
    ///
    /// # Arguments
    ///
    /// * `did_resolver` - a custom did resolver.
    #[wasm_bindgen(js_name = withDidResolver)]
    pub fn with_did_resolver(self, did_resolver: DIDResolver) -> Result<Self, JsError> {
        self.0
            .with_did_resolver(JsDIDResolver::new(did_resolver))
            .map(OID4VCIHolderBuilder)
            .map_err(JsError::from)
    }

    /// Use a specific Proof Of Possession generation parameters.
    ///
    /// # Arguments
    ///
    /// * `pop` - a custom PoP generation metadata.
    #[wasm_bindgen(js_name = withPop)]
    pub fn with_pop(self, pop: ProofOfPossessionMetadata) -> Self {
        OID4VCIHolderBuilder(self.0.with_pop(pop.0))
    }

    #[wasm_bindgen(js_name = withCredentialExtraVerification)]
    pub fn with_credential_extra_validation(
        self,
        options: Vec<CredentialExtraVerification>,
    ) -> Self {
        let options: Vec<_> = options.into_iter().map(Into::into).collect();
        OID4VCIHolderBuilder(self.0.with_credential_extra_verification(options))
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

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "InnerProofOfPossessionNotBefore")]
    pub type JsInnerProofOfPossessionNotBefore;
}

#[wasm_bindgen]
pub struct ProofOfPossessionMetadata(equs_sdk::vc::core::ProofOfPossessionMetadata);

#[wasm_bindgen]
pub struct ProofOfPossessionMetadataBuilder(equs_sdk::vc::core::ProofOfPossessionMetadata);

#[wasm_bindgen]
impl ProofOfPossessionMetadataBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        ProofOfPossessionMetadataBuilder(equs_sdk::vc::core::ProofOfPossessionMetadata::default())
    }

    /// Specifies Proof of Possession token lifetime.
    ///
    /// # Arguments
    ///
    /// * `lifetime_secs` - PoP token lifetime in seconds.
    #[wasm_bindgen(js_name = withLifetime)]
    pub fn with_lifetime(mut self, lifetime_secs: js_sys::Number) -> Self {
        self.0.lifetime = Duration::seconds(lifetime_secs.value_of() as i64);
        ProofOfPossessionMetadataBuilder(self.0)
    }

    /// Specifies Proof of Possession token valid not before generation strategy.
    ///
    /// # Arguments
    ///
    /// * `not_before` - PoP token valid not before generation strategy (plain JS object).
    #[wasm_bindgen(js_name = withNotBefore)]
    pub fn with_not_before(
        mut self,
        not_before: JsInnerProofOfPossessionNotBefore,
    ) -> Result<ProofOfPossessionMetadataBuilder, JsError> {
        let wasm_nb: WasmProofOfPossessionNotBefore = utils::convert_to_rust_object(not_before)?;
        self.0.not_before = Some(wasm_nb.try_into()?);
        Ok(ProofOfPossessionMetadataBuilder(self.0))
    }

    #[wasm_bindgen]
    pub fn build(self) -> ProofOfPossessionMetadata {
        ProofOfPossessionMetadata(self.0)
    }
}
