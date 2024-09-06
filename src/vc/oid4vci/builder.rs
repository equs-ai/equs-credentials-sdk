use crate::http::HttpClient;
use crate::reqwest::ReqwestClient;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vci as api;
use crate::vc::oid4vci::holder::HolderService;
use crate::vc::oid4vci::issuer::{IssuerService, TokenValidation};
use crate::vc::oid4vci::metadata::convert_metadata;
use crate::vc::oid4vci::token_validation::{ByJwks, Introspect};
use crate::vc::oid4vci::CredentialOffer;
use crate::{did, kms, vault, vc};
use oid4vci::openidconnect::JsonWebKeySetUrl;
use std::marker::PhantomData;
use url::Url;

/// `oid4vci` builder error.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum Error {
    #[error("Can't build service: {0}")]
    Build(String),
    #[error("Can't create default DID: {0}")]
    DID(#[from] did::Error),
    #[error("Can't create holder: {0}")]
    HolderInit(#[from] api::Error),
}

#[derive(Default, Clone)]
enum TokenParams {
    Introspect(Url, Option<String>),
    Jwks(Url),
    #[default]
    None,
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
    token_params: TokenParams,

    // services
    kms: KMS,
    http_client: Result<HC, Error>,

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
    pub fn new(kms: KMS, issuer_metadata: api::IssuerMetadata, key_metadata: KeyMetadata) -> Self {
        let http_client = ReqwestClient::new(false, true).map_err(|e| Error::Build(e.to_string()));

        Self {
            issuer_metadata,
            key_metadata,
            kms,
            http_client,
            token_params: TokenParams::None,
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
    pub fn token_validation_introspect(mut self, url: Url, header: Option<String>) -> Self {
        self.token_params = TokenParams::Introspect(url, header);
        self
    }

    /// Use a JWKS token validation.
    ///
    /// # Arguments
    ///
    /// * `url` - an url of JWKS.
    pub fn token_validation_jwks(mut self, url: Url) -> Self {
        self.token_params = TokenParams::Jwks(url);
        self
    }

    /// Builds an `Issuer`.
    ///
    /// # Returns
    ///
    /// An `Issuer` API on success.
    pub async fn build(self) -> Result<impl api::Issuer, Error> {
        let inner = vc::core::IssuerService::new(
            self.kms,
            convert_metadata(&self.issuer_metadata, self.key_metadata),
        );

        let http_client = self.http_client?;
        let token_validation = match self.token_params {
            TokenParams::Introspect(url, header) => {
                let introspect = Introspect::new(http_client, url.to_owned(), header.to_owned());
                TokenValidation::Introspect(introspect)
            }
            TokenParams::Jwks(url) => {
                let jwks = ByJwks::new(http_client, JsonWebKeySetUrl::from_url(url.to_owned()));
                TokenValidation::ByJwks(jwks)
            }
            TokenParams::None => TokenValidation::None,
        };

        let issuer = IssuerService::new(self.issuer_metadata, inner, token_validation);

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
    offer: Option<CredentialOffer>,
    metadata: Option<(api::IssuerMetadata, api::AuthorizationMetadata)>,
    iss_url: Option<String>,

    key_metadata: KeyMetadata,
    client_id: String,
    redirect_url: String,

    // services
    kms: KMS,
    vault: V,
    http_client: Result<HC, Error>,

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
    ///
    /// # Defaults
    ///
    /// * default `reqwest::Client` impl
    /// * "urn:ietf:wg:oauth:2.0:oob" as RedirectURL
    ///
    /// # Returns
    ///
    /// A new builder.
    pub fn new(kms: KMS, vault: V, key_metadata: KeyMetadata, client_id: String) -> Self {
        let http_client = ReqwestClient::new(false, true).map_err(|e| Error::Build(e.to_string()));

        Self {
            client_id,
            kms,
            vault,
            http_client,
            offer: None,
            metadata: None,
            iss_url: None,
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
    pub fn with_redirect_url(mut self, redirect_url: String) -> Self {
        self.redirect_url = redirect_url;
        self
    }

    /// Use an `Issuer` url to init the `Holder`.
    ///
    /// # Arguments
    ///
    /// * `issuer_url` - an `Issuer` API url.
    pub fn with_issuer_url(mut self, issuer_url: String) -> Self {
        self.iss_url = Some(issuer_url);
        self
    }

    /// Use a `CredentialOffer` to init the `Holder`.
    ///
    /// # Arguments
    ///
    /// * `offer` - a `CredentialOffer` issued by some `Issuer`.
    pub fn with_credential_offer(mut self, offer: CredentialOffer) -> Self {
        self.offer = Some(offer);
        self
    }

    /// Use metadata to init the `Holder`.
    ///
    /// # Arguments
    ///
    /// * `issuer_metadata` - an `IssuerMetadata` of the `Issuer`.
    /// * `authorization_metadata` - an `AuthorizationMetadata` of the corresponding Authorization Server.
    pub fn with_metadata(
        mut self,
        issuer_metadata: api::IssuerMetadata,
        authorization_metadata: api::AuthorizationMetadata,
    ) -> Self {
        self.metadata = Some((issuer_metadata, authorization_metadata));
        self
    }

    /// Use a specific `HttpClient`.
    ///
    /// # Arguments
    ///
    /// * `http_client` - a http client.
    pub fn with_http_client<HC_: HttpClient>(
        self,
        http_client: HC_,
    ) -> HolderBuilder<KH, KMS, V, HC_> {
        HolderBuilder {
            http_client: Ok(http_client),
            // copied
            offer: self.offer,
            metadata: self.metadata,
            iss_url: self.iss_url,
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
    ///
    /// # Errors
    ///
    /// One of the following options for initialization should be explicitly provided:
    /// * [HolderBuilder::with_issuer_url]
    /// * [HolderBuilder::with_credential_offer]
    /// * [HolderBuilder::with_metadata]
    pub async fn build(self) -> Result<impl api::Holder, Error> {
        let key_metadata = self.key_metadata;
        let holder_metadata = vc::core::HolderMetadata {
            client_id: self.client_id.clone(),
            key_metadata,
        };
        let inner = vc::core::HolderService::new(self.kms, self.vault, holder_metadata);

        let http_client = self.http_client?;

        let holder = match (self.offer, self.metadata, self.iss_url) {
            (Some(offer), _, _) => {
                HolderService::from_credential_offer(
                    inner,
                    http_client,
                    &offer,
                    self.client_id,
                    self.redirect_url,
                )
                .await
            }
            (_, Some((iss_meta, authz_meta)), _) => HolderService::from_metadata(
                inner,
                http_client,
                iss_meta,
                authz_meta,
                self.client_id,
                self.redirect_url,
            ),
            (_, _, Some(url)) => {
                HolderService::from_iss_url(
                    inner,
                    http_client,
                    url,
                    self.client_id,
                    self.redirect_url,
                )
                .await
            }
            _ => Err(Error::Build(
                "Set either offer, metadata or issuer url".to_string(),
            ))?,
        }?;

        Ok(holder)
    }
}
