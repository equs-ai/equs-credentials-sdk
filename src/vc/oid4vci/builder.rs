use crate::did::universal::{DIDResolver, UniversalResolver};
use crate::http::{HttpClient, HttpError, HttpSnafu};
use crate::nonce::{Nonce, NonceHandler};
use crate::reqwest::ReqwestClient;
use crate::reqwest::builder::ReqwestClientBuilder;
use crate::vc::core::DEFAULT_POP_LIFETIME_MINUTES;
use crate::vc::core::KeyMetadata;
use crate::vc::core::{DEFAULT_CRED_LIFETIME_DAYS, ProofOfPossessionMetadata};
use crate::vc::oid4vci as api;
use crate::vc::oid4vci::holder::HolderService;
use crate::vc::oid4vci::issuer::{IssuerService, TokenValidation};
use crate::vc::oid4vci::metadata::convert_metadata;
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};
use crate::vc::oid4vci::{CredentialExtraVerification, CredentialOfferParams};
use crate::vc::pop::ProofOfPossessionNotBefore;
use crate::{kms, vault, vc};
use async_trait::async_trait;
use common_macros::DebugError;
use oid4vci::types::CredentialConfigurationId;
use openidconnect::JsonWebKeySetUrl;
use snafu::{Location, Snafu};
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use time::Duration;
use tracing::{Level, debug, info, instrument};
use url::Url;

/// An `OID4VCI` Builder errors.
#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Builder error: {details}"))]
    Build {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

#[derive(Clone)]
enum TokenParams {
    Introspect(Url, Option<String>),
    Jwks(Url),
}

/// An enum containing options of discovery of the `Issuer` for a `Holder`.
#[derive(Debug, Clone)]
pub enum IssuerDiscovery {
    Url(String),
    Offer(CredentialOfferParams),
    Metadata(api::IssuerMetadata, api::AuthorizationMetadata),
}

/// A builder for instantiating `oid4vci` `Issuer`.
pub struct IssuerBuilder<KH, KMS, HC, NH>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    HC: HttpClient,
    NH: NonceHandler,
{
    // data
    issuer_metadata: api::IssuerMetadata,
    key_metadata: KeyMetadata,
    token_params: Option<TokenParams>,
    clock_skew: Option<time::Duration>,
    cred_conf_ids_with_key_metadata: HashMap<String, KeyMetadata>,
    default_cred_lifetime: Duration,
    cred_lifetime_per_cred_conf_id: HashMap<CredentialConfigurationId, Duration>,
    credential_extra_verification: Vec<CredentialExtraVerification>,

    // services
    kms: KMS,
    http_client: Result<HC, HttpError>,
    nonce_handler: Option<NH>,
    did_resolver: UniversalResolver,

    _marker: PhantomData<KH>,
}

impl<KH, KMS> IssuerBuilder<KH, KMS, ReqwestClient, InternalNonceHandler>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    /// Returns a new `Builder` initialized with defaults.
    ///
    /// # Arguments
    ///
    /// * `kms` - an inner KMS.
    /// * `issuer_metadata` - an `IssuerMetadata`.
    /// * `key_metadata` - a default `KeyMetadata` with `DIDURL` and `KID` to be used for signing operations.
    ///    If you want to specify a dedicated `KeyMedata` per `credential_configuration_id`, please
    ///    use `with_dedicated_key_metadata` builder function
    ///
    /// # Defaults
    ///
    /// * default `reqwest::Client` impl
    /// * no token validation
    ///
    /// # Returns
    ///
    /// A new builder.
    #[instrument(
        level = Level::TRACE,
        skip(kms),
    )]
    pub fn new(kms: KMS, issuer_metadata: api::IssuerMetadata, key_metadata: KeyMetadata) -> Self {
        let http_client = ReqwestClientBuilder::new().build().map_err(|e| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        });

        info!("oid4vci-issuer builder is initialized");

        Self {
            issuer_metadata,
            key_metadata,
            kms,
            http_client,
            nonce_handler: None,
            token_params: None,
            clock_skew: None,
            default_cred_lifetime: Duration::days(DEFAULT_CRED_LIFETIME_DAYS),
            cred_lifetime_per_cred_conf_id: HashMap::new(),
            cred_conf_ids_with_key_metadata: Default::default(),
            did_resolver: UniversalResolver::default(),
            credential_extra_verification: Default::default(),
            _marker: Default::default(),
        }
    }
}

impl<KH, KMS, HC, NH> IssuerBuilder<KH, KMS, HC, NH>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    HC: HttpClient + 'static,
    NH: NonceHandler,
{
    /// Use a specific `HttpClient`.
    ///
    /// # Arguments
    ///
    /// * `http_client` - a http client.
    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn with_http_client<HC_: HttpClient + 'static>(
        self,
        http_client: HC_,
    ) -> IssuerBuilder<KH, KMS, HC_, NH> {
        IssuerBuilder {
            http_client: Ok(http_client),
            // copied
            issuer_metadata: self.issuer_metadata,
            key_metadata: self.key_metadata,
            token_params: self.token_params,
            clock_skew: self.clock_skew,
            kms: self.kms,
            default_cred_lifetime: self.default_cred_lifetime,
            cred_lifetime_per_cred_conf_id: self.cred_lifetime_per_cred_conf_id,
            nonce_handler: self.nonce_handler,
            cred_conf_ids_with_key_metadata: Default::default(),
            did_resolver: self.did_resolver,
            credential_extra_verification: Default::default(),
            _marker: Default::default(),
        }
    }

    /// Use an introspect token validation.
    ///
    /// # Arguments
    ///
    /// * `url` - an url of token introspection endpoint.
    /// * `header` - an optional Authz header for introspection calls.
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn token_validation_introspect(mut self, url: Url, header: Option<String>) -> Self {
        self.token_params = Some(TokenParams::Introspect(url, header));
        self
    }

    /// Use a JWKS token validation.
    ///
    /// # Arguments
    ///
    /// * `url` - an url of JWKS.
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn token_validation_jwks(mut self, url: Url) -> Self {
        self.token_params = Some(TokenParams::Jwks(url));
        self
    }

    /// Use a Nonce Handler to enable the `Nonce` generation and validation. Generated `Nonce` will be
    /// incorporated into proofs in the Credential Request.
    ///
    /// # Arguments
    ///
    /// * `nonce_handler` - an implementation of `NonceHandler` trait.
    #[instrument(
        level = Level::TRACE,
        skip(self, nonce_handler),
    )]
    pub fn with_nonce_handler<NH_: NonceHandler>(
        self,
        nonce_handler: NH_,
    ) -> IssuerBuilder<KH, KMS, HC, NH_> {
        IssuerBuilder {
            nonce_handler: Some(nonce_handler),
            // copied
            http_client: self.http_client,
            issuer_metadata: self.issuer_metadata,
            key_metadata: self.key_metadata,
            token_params: self.token_params,
            clock_skew: self.clock_skew,
            kms: self.kms,
            default_cred_lifetime: self.default_cred_lifetime,
            cred_lifetime_per_cred_conf_id: self.cred_lifetime_per_cred_conf_id,
            cred_conf_ids_with_key_metadata: Default::default(),
            did_resolver: self.did_resolver,
            credential_extra_verification: Default::default(),
            _marker: Default::default(),
        }
    }

    /// Sets a `KeyMetadata` to be used for signing operations of the credential
    /// with the corresponding `credential_configuration_id`.
    ///
    /// # Arguments
    ///
    /// * `credential_configuration_id` - credential configuration id predefined on `IssuerMetadata`.
    /// * `key_metadata` - a `KeyMetadata` with `DIDURL` and `KID` to be used for signing operations.
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_dedicated_key_metadata(
        mut self,
        credential_configuration_id: &str,
        key_metadata: &KeyMetadata,
    ) -> Self {
        self.cred_conf_ids_with_key_metadata.insert(
            credential_configuration_id.to_owned(),
            key_metadata.to_owned(),
        );

        self
    }

    /// Sets the duration for clock skew tolerance.
    ///
    /// Set a duration to account for potential clock skew between different systems.
    /// It is used while performing time-based validations.
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration to set for clock skew tolerance. This value defines
    ///   the amount of time to be considered as permissible skew in seconds, milliseconds,
    ///   or other time units supported by `time::Duration`.
    ///
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_clock_skew(mut self, duration: time::Duration) -> Self {
        self.clock_skew = Some(duration);
        self
    }

    /// Sets the creds lifetime.
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration to set for cred lifetime.
    ///   or other time units supported by `time::Duration`.
    ///
    #[instrument(
        level = Level::TRACE,
        skip(self)
    )]
    pub fn with_default_cred_lifetime(mut self, duration: Duration) -> Self {
        self.default_cred_lifetime = duration;
        self
    }

    /// Sets the credential lifetime for given credential configuration id.
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration to set for cred lifetime.
    ///   or other time units supported by `time::Duration`.
    ///
    #[instrument(
        level = Level::TRACE,
        skip(self)
    )]
    pub fn with_credential_lifetime(
        mut self,
        credential_configuration_id: String,
        duration: Duration,
    ) -> Self {
        self.cred_lifetime_per_cred_conf_id.insert(
            CredentialConfigurationId::new(credential_configuration_id),
            duration,
        );

        self
    }

    /// Sets custom did resolver for the Issuer.
    ///
    /// This method allows providing a custom did resolver.
    /// If provided, it can be used to resolve did into the did document
    ///
    /// # Errors
    ///
    /// [Error::Build] - if did method already exists.
    ///
    /// # Arguments
    ///
    /// * `did_resolver` - did resolver implementing `DIDResolver`.
    #[instrument(
        level = Level::TRACE,
        skip(self, did_resolver),
    )]
    pub fn with_did_resolver(
        mut self,
        did_resolver: impl DIDResolver + 'static,
    ) -> Result<Self, Error> {
        let mut universal_resolver = UniversalResolver::default();
        universal_resolver
            .add_resolver(did_resolver)
            .map_err(|err| {
                BuildSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;
        self.did_resolver = universal_resolver;
        Ok(self)
    }

    /// Builds an `Issuer`.
    ///
    /// # Returns
    ///
    /// An `Issuer` API on success.
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
    )]
    pub async fn build(self) -> Result<impl api::Issuer, Error> {
        let issuer_metadata = convert_metadata(
            &self.issuer_metadata,
            &self.cred_conf_ids_with_key_metadata,
            &self.key_metadata,
            self.default_cred_lifetime,
            self.cred_lifetime_per_cred_conf_id,
        )
        .map_err(|e| {
            BuildSnafu {
                details: format!("Cannot convert metadata: {e}"),
            }
            .build()
        })?;
        let inner = vc::core::IssuerService::new(self.kms, issuer_metadata, self.did_resolver);

        let http_client = self.http_client.map_err(|e| {
            BuildSnafu {
                details: format!("Cannot initialize http client: {e}"),
            }
            .build()
        })?;
        let token_validation = match self.token_params {
            Some(TokenParams::Introspect(url, header)) => {
                let introspect = Introspect::new(http_client, url.to_owned(), header.to_owned());
                Some(TokenValidation::Introspect(introspect))
            }
            Some(TokenParams::Jwks(url)) => {
                let jwks = ByJwks::new(http_client, JsonWebKeySetUrl::from_url(url.to_owned()));
                Some(TokenValidation::ByJwks(jwks))
            }
            _ => None,
        };

        if self.issuer_metadata.nonce_endpoint().is_some() && self.nonce_handler.is_none() {
            BuildSnafu {
                details: "Nonce Handler is required while enabling nonce endpoint. \
                Please provide the Nonce Handler implementation by calling 'nonce_handler' builder function".to_string(),
            }
                .fail()?
        }

        let issuer = IssuerService::new(
            self.issuer_metadata,
            inner,
            self.nonce_handler,
            token_validation,
            self.clock_skew,
        );

        info!("oid4vci-issuer service is initialized");

        Ok(issuer)
    }
}

/// A builder for instantiating `oid4vci` `Holder`.
pub struct HolderBuilder<KH, KMS, V, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
    HC: HttpClient,
{
    // data
    iss_discovery: IssuerDiscovery,

    client_id: String,
    redirect_url: String,

    credential_extra_verification: Option<Vec<CredentialExtraVerification>>,

    // services
    kms: KMS,
    vault: V,
    http_client: Arc<HC>,
    pop: ProofOfPossessionMetadata,
    did_resolver: UniversalResolver,

    _marker: PhantomData<KH>,
}

impl<KH, KMS, V, HC> HolderBuilder<KH, KMS, V, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
    HC: HttpClient,
{
    /// Returns a new `Builder` initialized with defaults.
    ///
    /// # Arguments
    ///
    /// * `kms` - an inner [kms::Kms].
    /// * `vault` - an inner [vault::Vault].
    /// * `client_id` - a client ID.
    /// * `iss_discovery` - a data to discover the `Issuer`.
    ///   Either `CredentialOffer`, `IssuerMetadata` and `AuthorizationMetadata` or `Issuer` url.
    ///
    /// # Defaults
    ///
    /// * default `reqwest::Client` impl
    /// * "urn:ietf:wg:oauth:2.0:oob" as RedirectURL
    ///
    /// # Returns
    ///
    /// A new builder.
    #[instrument(
        level = Level::TRACE,
        skip(kms, vault, http_client),
    )]
    pub fn new(
        kms: KMS,
        vault: V,
        client_id: String,
        iss_discovery: IssuerDiscovery,
        http_client: HC,
    ) -> Self {
        info!("oid4vci-holder builder is initialized");

        Self {
            client_id,
            kms,
            vault,
            http_client: Arc::new(http_client),
            iss_discovery,
            redirect_url: "urn:ietf:wg:oauth:2.0:oob".to_string(),
            pop: ProofOfPossessionMetadataBuilder::new().build(),
            did_resolver: UniversalResolver::default(),
            credential_extra_verification: Default::default(),
            _marker: Default::default(),
        }
    }
}

impl<KH, KMS, V, HC> HolderBuilder<KH, KMS, V, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
    HC: HttpClient + 'static,
{
    /// Use a specific `RedirectUrl`.
    ///
    /// # Arguments
    ///
    /// * `redirect_url` - an Oauth2 Redirect Url used by authorization endpoint.
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_redirect_url(mut self, redirect_url: String) -> Self {
        self.redirect_url = redirect_url;
        self
    }

    /// Use a specific `Proof of Possession` generation config.
    ///
    /// # Arguments
    ///
    /// * `pop` - Proof Of Possession generation config
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_pop(mut self, pop: ProofOfPossessionMetadata) -> Self {
        self.pop = pop;
        self
    }

    /// Sets custom did resolver for the Holder.
    ///
    /// This method allows providing a custom did resolver.
    /// If provided, it can be used to resolve did into the did document
    ///
    /// # Errors
    ///
    /// [Error::Build] - if did method already exists.
    ///
    /// # Arguments
    ///
    /// * `did_resolver` - did resolver implementing `DIDResolver`.
    #[instrument(
        level = Level::TRACE,
        skip(self, did_resolver),
    )]
    pub fn with_did_resolver(
        mut self,
        did_resolver: impl DIDResolver + 'static,
    ) -> Result<Self, Error> {
        let mut universal_resolver = UniversalResolver::default();
        universal_resolver
            .add_resolver(did_resolver)
            .map_err(|err| {
                BuildSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;
        self.did_resolver = universal_resolver;
        Ok(self)
    }

    /// Sets issued credential extra verification options.
    ///
    /// # Arguments
    ///
    /// * `options` - list of credential extra verification options.
    #[instrument(
        level = Level::TRACE,
        skip(self),
    )]
    pub fn with_credential_extra_verification(
        mut self,
        options: Vec<CredentialExtraVerification>,
    ) -> Self {
        self.credential_extra_verification = Some(options);
        self
    }

    /// Builds a `Holder`.
    ///
    /// # Returns
    ///
    /// A `Holder` API on success.
    #[instrument(
        level = Level::TRACE,
        err(),
        skip(self),
    )]
    pub async fn build(self) -> Result<impl api::Holder, Error> {
        let holder_metadata = vc::core::HolderMetadata {
            client_id: self.client_id.clone(),
            pop: self.pop,
        };

        let inner = vc::core::HolderService::new(
            self.kms,
            self.vault,
            holder_metadata,
            self.did_resolver,
            self.http_client.clone(),
        );

        let holder = match self.iss_discovery {
            IssuerDiscovery::Offer(offer) => {
                debug!("offer: {:?}", offer);

                HolderService::from_credential_offer(
                    inner,
                    self.http_client,
                    &offer,
                    self.client_id,
                    self.redirect_url,
                    self.credential_extra_verification,
                )
                .await
            }
            IssuerDiscovery::Metadata(iss_meta, authz_meta) => {
                debug!(
                    "issuer metadata: {:?}, authz metadata: {:?}",
                    iss_meta, authz_meta
                );

                HolderService::from_metadata(
                    inner,
                    self.http_client,
                    iss_meta,
                    authz_meta,
                    self.client_id,
                    self.redirect_url,
                    self.credential_extra_verification,
                )
            }
            IssuerDiscovery::Url(url) => {
                debug!("issuer discovery url: {url}");

                HolderService::from_iss_url(
                    inner,
                    self.http_client,
                    url,
                    self.client_id,
                    self.redirect_url,
                    self.credential_extra_verification,
                )
                .await
            }
        }
        .map_err(|e| {
            BuildSnafu {
                details: format!("Cannot initialize Holder service: {:?}", e),
            }
            .build()
        })?;

        info!("oid4vci-holder service is initialized");

        Ok(holder)
    }
}

/// DON'T USE: The following struct is only used to work around a compilation problem related
/// to type inference when using the IssuerBuilder::new() function
pub struct InternalNonceHandler {
    _private: (),
}

pub struct ProofOfPossessionMetadataBuilder {
    lifetime: Duration,
    not_before: Option<ProofOfPossessionNotBefore>,
}

impl ProofOfPossessionMetadataBuilder {
    pub fn new() -> Self {
        Self {
            lifetime: Duration::minutes(DEFAULT_POP_LIFETIME_MINUTES),
            not_before: None,
        }
    }

    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    pub fn with_not_before(mut self, not_before: ProofOfPossessionNotBefore) -> Self {
        self.not_before = Some(not_before);
        self
    }

    pub fn build(self) -> ProofOfPossessionMetadata {
        ProofOfPossessionMetadata {
            lifetime: self.lifetime,
            not_before: self.not_before,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NonceHandler for InternalNonceHandler {
    async fn generate(&self) -> crate::nonce::Result<Nonce> {
        unimplemented!()
    }

    async fn validate(&self, nonce: &Nonce) -> crate::nonce::Result<bool> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceHandler;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::test::mock_http_once;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::oid4vci::IssuerUrl;
    use crate::vc::oid4vci::tests::fixtures::{
        AUTH_REDIRECT_URL, ISSUER_URL, SCOPE, SampleIssuerMetadata, sample_authorization_metadata,
    };
    use oauth2::http::{Method, StatusCode};
    use oid4vci::credential_offer::CredentialOfferParameters;
    use oid4vci::types::CredentialConfigurationId;
    use rstest::rstest;

    pub const ISSUER_OIDC_URL: &str =
        "https://issuer-backend.com/.well-known/openid-credential-issuer";
    pub const AUTH_SERVER_OIDC_URL: &str =
        "https://authz-backend.com/.well-known/openid-configuration";

    #[tokio::test]
    async fn building_issuer_works() {
        let http_client = MockHttpClient::new();
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceHandler::default();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let builder =
            IssuerBuilder::new(kms, SampleIssuerMetadata::with_sdjwtvc_conf(), key_metadata)
                .with_nonce_handler(nonce_gen)
                .token_validation_jwks(Url::parse("http://issuer.org/certs").unwrap())
                .with_clock_skew(time::Duration::minutes(1))
                .with_http_client(http_client);

        let result = builder.build().await;

        result.unwrap();
    }

    #[tokio::test]
    async fn building_issuer_works_when_nonce_handler_is_not_provided() {
        let http_client = MockHttpClient::new();
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceHandler::default();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let mut metadata = SampleIssuerMetadata::with_sdjwtvc_conf();
        metadata = metadata.set_nonce_endpoint(None);

        let builder = IssuerBuilder::new(kms, metadata, key_metadata)
            .token_validation_jwks(Url::parse("http://issuer.org/certs").unwrap())
            .with_clock_skew(time::Duration::minutes(1))
            .with_http_client(http_client);

        let result = builder.build().await;

        result.unwrap();
    }

    #[tokio::test]
    async fn building_issuer_works_when_cred_lifetime_is_set_per_cred_conf_id() {
        let http_client = MockHttpClient::new();
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceHandler::default();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let mut metadata = SampleIssuerMetadata::with_sdjwtvc_conf();
        metadata = metadata.set_nonce_endpoint(None);

        let cred_configuration_id = metadata
            .credential_configurations_supported()
            .first()
            .unwrap()
            .id()
            .to_string();
        let builder = IssuerBuilder::new(kms, metadata, key_metadata)
            .with_credential_lifetime(cred_configuration_id, Duration::days(365));
        let result = builder.build().await;

        result.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Nonce Handler is required while enabling nonce endpoint")]
    async fn building_issuer_fails_when_nonce_handler_is_provided_but_nonce_endpoint_is_missed() {
        let http_client = MockHttpClient::new();
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceHandler::default();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let builder =
            IssuerBuilder::new(kms, SampleIssuerMetadata::with_sdjwtvc_conf(), key_metadata)
                .token_validation_jwks(Url::parse("http://issuer.org/certs").unwrap())
                .with_clock_skew(time::Duration::minutes(1))
                .with_http_client(http_client);

        let result = builder.build().await;

        result.unwrap();
    }

    #[rstest]
    #[case::from_offer(issuer_discovery_from_offer())]
    #[case::from_url(issuer_discovery_from_url())]
    #[case::from_metadata(issuer_discovery_from_metadata())]
    #[tokio::test]
    async fn building_holder_works(#[case] discovery: IssuerDiscovery) {
        let kms = LocalKms::new();

        let mut http_client = MockHttpClient::new();
        match discovery {
            IssuerDiscovery::Url(_) | IssuerDiscovery::Offer(_) => {
                mock_http_once(
                    &mut http_client,
                    Method::GET,
                    Url::parse(ISSUER_OIDC_URL).unwrap(),
                    SampleIssuerMetadata::with_sdjwtvc_conf(),
                    StatusCode::OK,
                );

                mock_http_once(
                    &mut http_client,
                    Method::GET,
                    Url::parse(AUTH_SERVER_OIDC_URL).unwrap(),
                    sample_authorization_metadata(),
                    StatusCode::OK,
                );
            }
            _ => {}
        }

        let vault = InMemVault::new();
        HolderBuilder::new(
            kms,
            vault,
            "fake_client_id".to_string(),
            discovery,
            http_client,
        )
        .with_redirect_url(AUTH_REDIRECT_URL.to_string())
        .with_credential_extra_verification(vec![
            CredentialExtraVerification::CredentialIssuerIdentifier,
        ])
        .build()
        .await
        .unwrap();
    }

    fn issuer_discovery_from_offer() -> IssuerDiscovery {
        let credential_offer = CredentialOfferParameters {
            credential_issuer: IssuerUrl::new(ISSUER_URL.to_string()).unwrap(),
            credential_configuration_ids: vec![CredentialConfigurationId::new(SCOPE.to_string())],
            grants: None,
        };

        IssuerDiscovery::Offer(credential_offer)
    }

    fn issuer_discovery_from_url() -> IssuerDiscovery {
        IssuerDiscovery::Url(ISSUER_URL.to_owned())
    }

    fn issuer_discovery_from_metadata() -> IssuerDiscovery {
        IssuerDiscovery::Metadata(
            SampleIssuerMetadata::with_sdjwtvc_conf(),
            sample_authorization_metadata(),
        )
    }
}
