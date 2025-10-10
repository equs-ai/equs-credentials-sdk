use crate::did::resolver::{DIDResolver, JsDIDResolver};
use crate::http::ReqwestHttpClient;
use crate::kms::{JsKeyHandle, JsKms, Kms};
use crate::utils;
use crate::vault::{JsVault, Vault};
use crate::vc::oid4vci::holder::CredentialExtraVerification;
use crate::vc::oid4vci::holder::OID4VCIHolder;
use crate::vc::oid4vci::{OID4VCICredentialOffer, OID4VCIIssuerMetadata};
use agent_sdk::vc::oid4vci::HolderBuilder;
use agent_sdk::{Duration, OffsetDateTime};
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
pub struct ProofOfPossessionMetadata(agent_sdk::vc::core::ProofOfPossessionMetadata);

#[wasm_bindgen]
pub struct ProofOfPossessionMetadataBuilder(agent_sdk::vc::core::ProofOfPossessionMetadata);

#[wasm_bindgen]
impl ProofOfPossessionMetadataBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        ProofOfPossessionMetadataBuilder(agent_sdk::vc::core::ProofOfPossessionMetadata::default())
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
    /// * `not_before` - PoP token valid not before generation strategy.
    #[wasm_bindgen(js_name = withNotBefore)]
    pub fn with_not_before(mut self, not_before: ProofOfPossessionNotBefore) -> Self {
        self.0.not_before = Some(not_before.0);
        ProofOfPossessionMetadataBuilder(self.0)
    }

    #[wasm_bindgen]
    pub fn build(self) -> ProofOfPossessionMetadata {
        ProofOfPossessionMetadata(self.0)
    }
}

#[wasm_bindgen]
pub struct ProofOfPossessionNotBefore(agent_sdk::vc::core::ProofOfPossessionNotBefore);

#[wasm_bindgen]
impl ProofOfPossessionNotBefore {
    /// Set Proof of Possession token "valid not before" matching "issued at" time.
    #[wasm_bindgen(js_name = asIssuedAt)]
    pub fn issued_at() -> Self {
        Self(agent_sdk::vc::core::ProofOfPossessionNotBefore::AsIssuedAt)
    }

    /// Set Proof of Possession token "valid not before" as a given moment in time.
    ///
    /// # Arguments
    ///
    /// * `time` - a moment in time.
    #[wasm_bindgen]
    pub fn fixed(time: js_sys::Date) -> Result<Self, JsError> {
        Ok(Self(
            agent_sdk::vc::core::ProofOfPossessionNotBefore::Fixed(
                OffsetDateTime::from_unix_timestamp(time.get_utc_seconds() as i64)
                    .map_err(|e| JsError::new(&format!("{:?}", e)))?,
            ),
        ))
    }

    /// Set Proof of Possession token "valid not before" with a given delay from "issued at" time.
    ///
    /// # Arguments
    ///
    /// * `duration_secs` - delay in seconds.
    #[wasm_bindgen]
    pub fn delay(duration_secs: js_sys::Number) -> Self {
        Self(agent_sdk::vc::core::ProofOfPossessionNotBefore::Delay(
            Duration::seconds(duration_secs.value_of() as i64),
        ))
    }

    /// Set Proof of Possession token "valid not before" with a given leeway from "issued at" time.
    ///
    /// # Arguments
    ///
    /// * `leeway_secs` - leeway in seconds.
    #[wasm_bindgen]
    pub fn leeway(duration_secs: js_sys::Number) -> Self {
        Self(agent_sdk::vc::core::ProofOfPossessionNotBefore::Leeway(
            Duration::seconds(duration_secs.value_of() as i64),
        ))
    }
}
