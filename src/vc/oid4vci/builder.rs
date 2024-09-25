use crate::http::{HttpClient, HttpError, HttpSnafu};
use crate::reqwest::ReqwestClient;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vci as api;
use crate::vc::oid4vci::holder::HolderService;
use crate::vc::oid4vci::issuer::{IssuerService, TokenValidation};
use crate::vc::oid4vci::metadata::convert_metadata;
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};
use crate::vc::oid4vci::CredentialOffer;
use crate::{kms, vault, vc};
use oid4vci::openidconnect::JsonWebKeySetUrl;
use snafu::{Location, Snafu};
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use tracing::{debug, info, instrument, Level};
use url::Url;

/// An `OID4VCI` Builder errors.
#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Builder error at {location}\n Cause: {details}"))]
    Build {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        let mut error: &dyn std::error::Error = self;
        while let Some(source) = error.source() {
            write!(fmt, "\n Cause: {}", source)?;
            error = source;
        }

        Ok(())
    }
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
    Offer(CredentialOffer),
    Metadata(api::IssuerMetadata, api::AuthorizationMetadata),
}

/// A builder for instantiating `oid4vci` `Issuer`.
pub struct IssuerBuilder<KH, KMS, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    HC: HttpClient,
{
    // data
    issuer_metadata: api::IssuerMetadata,
    key_metadata: KeyMetadata,
    token_params: Option<TokenParams>,
    cred_conf_ids_with_key_metadata: HashMap<String, KeyMetadata>,

    // services
    kms: KMS,
    http_client: Result<HC, HttpError>,

    _marker: PhantomData<KH>,
}

impl<KH, KMS> IssuerBuilder<KH, KMS, ReqwestClient>
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
        let http_client = ReqwestClient::new(false, true).map_err(|e| {
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
            token_params: None,
            cred_conf_ids_with_key_metadata: Default::default(),
            _marker: Default::default(),
        }
    }
}

impl<KH, KMS, HC> IssuerBuilder<KH, KMS, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    HC: HttpClient,
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
    pub fn with_http_client<HC_: HttpClient>(
        self,
        http_client: HC_,
    ) -> IssuerBuilder<KH, KMS, HC_> {
        IssuerBuilder {
            http_client: Ok(http_client),
            // copied
            issuer_metadata: self.issuer_metadata,
            key_metadata: self.key_metadata,
            token_params: self.token_params,
            kms: self.kms,
            cred_conf_ids_with_key_metadata: Default::default(),
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
        )
        .map_err(|e| {
            BuildSnafu {
                details: format!("Cannot convert metadata: {e}"),
            }
            .build()
        })?;
        let inner = vc::core::IssuerService::new(self.kms, issuer_metadata);

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

        let issuer = IssuerService::new(self.issuer_metadata, inner, token_validation);

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

    // services
    kms: KMS,
    vault: V,
    http_client: Result<HC, HttpError>,

    _marker: PhantomData<KH>,
}

impl<KH, KMS, V> HolderBuilder<KH, KMS, V, ReqwestClient>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
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
        skip(kms, vault),
    )]
    pub fn new(kms: KMS, vault: V, client_id: String, iss_discovery: IssuerDiscovery) -> Self {
        let http_client = ReqwestClient::new(false, true).map_err(|e| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        });

        info!("oid4vci-holder builder is initialized");

        Self {
            client_id,
            kms,
            vault,
            http_client,
            iss_discovery,
            redirect_url: "urn:ietf:wg:oauth:2.0:oob".to_string(),
            _marker: Default::default(),
        }
    }
}

impl<KH, KMS, V, HC> HolderBuilder<KH, KMS, V, HC>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
    V: vault::Vault,
    HC: HttpClient,
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

    /// Use a specific `HttpClient`.
    ///
    /// # Arguments
    ///
    /// * `http_client` - a http client.
    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    pub fn with_http_client<HC_: HttpClient>(
        self,
        http_client: HC_,
    ) -> HolderBuilder<KH, KMS, V, HC_> {
        HolderBuilder {
            http_client: Ok(http_client),
            // copied
            iss_discovery: self.iss_discovery,
            client_id: self.client_id,
            redirect_url: self.redirect_url,
            kms: self.kms,
            vault: self.vault,
            _marker: Default::default(),
        }
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
        };
        let inner = vc::core::HolderService::new(self.kms, self.vault, holder_metadata);

        let http_client = self.http_client.map_err(|e| {
            BuildSnafu {
                details: format!("Cannot initialize http client: {e}"),
            }
            .build()
        })?;

        let holder = match self.iss_discovery {
            IssuerDiscovery::Offer(offer) => {
                debug!("offer: {:?}", offer);

                HolderService::from_credential_offer(
                    inner,
                    http_client,
                    &offer,
                    self.client_id,
                    self.redirect_url,
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
                    http_client,
                    iss_meta,
                    authz_meta,
                    self.client_id,
                    self.redirect_url,
                )
            }
            IssuerDiscovery::Url(url) => {
                debug!("issuer discovery url: {url}");

                HolderService::from_iss_url(
                    inner,
                    http_client,
                    url,
                    self.client_id,
                    self.redirect_url,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::test::mock_http_once;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::oid4vci::tests::fixtures::{
        sample_authorization_metadata, SampleIssuerMetadata, AUTH_REDIRECT_URL, ISSUER_URL, SCOPE,
    };
    use oauth2::http::{Method, StatusCode};
    use oauth2::Scope;
    use oid4vci::credential_offer::{CredentialOfferFormat, CredentialOfferParameters};
    use oid4vci::openidconnect::IssuerUrl;
    use rstest::rstest;

    pub const ISSUER_OIDC_URL: &str =
        "https://issuer-backend.com/.well-known/openid-credential-issuer";
    pub const AUTH_SERVER_OIDC_URL: &str =
        "https://authz-backend.com/.well-known/openid-configuration";

    #[tokio::test]
    async fn building_issuer_works() {
        let http_client = MockHttpClient::new();
        let kms = LocalKms::new();
        let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

        let builder =
            IssuerBuilder::new(kms, SampleIssuerMetadata::with_sdjwtvc_conf(), key_metadata)
                .token_validation_jwks(Url::parse("http://issuer.org/certs").unwrap())
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
        let builder = HolderBuilder::new(kms, vault, "fake_client_id".to_string(), discovery)
            .with_http_client(http_client)
            .with_redirect_url(AUTH_REDIRECT_URL.to_string());

        let result = builder.build().await;

        result.unwrap();
    }

    fn issuer_discovery_from_offer() -> IssuerDiscovery {
        let credential_offer = CredentialOfferParameters::new(
            IssuerUrl::new(ISSUER_URL.to_string()).unwrap(),
            vec![CredentialOfferFormat::Reference(Scope::new(
                SCOPE.to_string(),
            ))],
            None,
        );

        IssuerDiscovery::Offer(CredentialOffer::Value { credential_offer })
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
