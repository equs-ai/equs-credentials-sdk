use crate::http::{HttpClient, HttpError};
use crate::reqwest::builder::ReqwestClientBuilder;
use crate::reqwest::ReqwestClient;
use crate::vc::oid4vci::{CredentialOffer, CredentialOfferParams, CredentialOfferRequest};
use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{info, instrument, Level};
use url::Url;

/// An `OID4VCI` Credential offer resolver errors.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Offer resolution error"))]
    Resolve {
        source: anyhow::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Http error"))]
    HttpClient {
        source: HttpError,
        #[snafu(implicit)]
        location: Location,
    },
}

pub struct CredentialOfferResolver<HC>
where
    HC: HttpClient,
{
    http_client: Arc<HC>,
}

impl CredentialOfferResolver<ReqwestClient> {
    /// Returns a new `CredentialOfferResolver` to resolve `CredentialOfferParams`
    ///
    /// # Defaults
    ///
    /// * default [ReqwestClient] http client will be used.
    /// To use custom http client please use `with_http_client`
    ///
    /// # Returns
    ///
    /// A new resolver.
    ///
    /// # Errors
    ///
    /// * [Error::HttpClient] - fails to create http client.
    #[instrument(
        level = Level::TRACE,
        err(),
    )]
    pub fn new() -> Result<Self, Error> {
        let http_client = ReqwestClientBuilder::new()
            .build()
            .context(HttpClientSnafu)?;

        info!("oid4vci credential resolver is initialized");

        Ok(Self {
            http_client: Arc::new(http_client),
        })
    }
}

impl<HC: HttpClient> CredentialOfferResolver<HC> {
    /// Returns a new [CredentialOfferResolver] to resolve credential offer params [CredentialOfferParams]
    /// by using a specific [HttpClient].
    ///
    /// # Arguments
    ///
    /// * `http_client` - a custom http client.
    ///
    /// # Returns
    ///
    /// A new credential offer resolver.
    pub fn with_http_client(http_client: HC) -> Self {
        Self {
            http_client: Arc::new(http_client),
        }
    }

    /// Resolves the [CredentialOfferParams] from the credential offer uri
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
    /// * [Error::Resolve] - when resolution of credential offer fails.
    #[instrument(level = Level::TRACE, skip(self), ret(), err())]
    pub async fn resolve(&self, offer_uri: Url) -> Result<CredentialOfferParams, Error> {
        info!("resolving credential offer is started");

        let offer_req =
            CredentialOfferRequest::from_url_checked(offer_uri).context(ResolveSnafu)?;
        let offer = CredentialOffer::from_request(offer_req).context(ResolveSnafu)?;

        let client = self.http_client.clone();
        let http_closure = move |req| {
            let client = client.clone();
            Box::pin(async move { client.async_call(req).await })
        };

        let offer_params = offer
            .resolve_async(&http_closure)
            .await
            .context(ResolveSnafu)?;

        info!("credential offer is resolved");

        Ok(offer_params)
    }
}
