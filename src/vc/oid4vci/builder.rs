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
use std::fmt::Debug;
use std::marker::PhantomData;
use tracing::{info, instrument, Level};
use url::Url;

/// An `OID4VCI` Builder errors.
#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    Build {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;
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
    /// * `key_metadata` - a `KeyMetadata` with `DIDURL` and `KID` to be used for signing operations.
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
        let inner = vc::core::IssuerService::new(
            self.kms,
            convert_metadata(&self.issuer_metadata, self.key_metadata),
        );

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

    key_metadata: KeyMetadata,
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
    /// * `key_metadata` - a `KeyMetadata` with `DIDURL` and `KID` to be used for signing operations.
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
    pub fn new(
        kms: KMS,
        vault: V,
        key_metadata: KeyMetadata,
        client_id: String,
        iss_discovery: IssuerDiscovery,
    ) -> Self {
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
            key_metadata,
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
            key_metadata: self.key_metadata,
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
        let key_metadata = self.key_metadata;
        let holder_metadata = vc::core::HolderMetadata {
            client_id: self.client_id.clone(),
            key_metadata,
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
                HolderService::from_credential_offer(
                    inner,
                    http_client,
                    &offer,
                    self.client_id,
                    self.redirect_url,
                )
                .await
            }
            IssuerDiscovery::Metadata(iss_meta, authz_meta) => HolderService::from_metadata(
                inner,
                http_client,
                iss_meta,
                authz_meta,
                self.client_id,
                self.redirect_url,
            ),
            IssuerDiscovery::Url(url) => {
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
                details: format!("Cannot initialize Holder service: {e}"),
            }
            .build()
        })?;

        info!("oid4vci-holder service is initialized");

        Ok(holder)
    }
}
