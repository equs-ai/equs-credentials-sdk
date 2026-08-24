use crate::http::{HttpClient, WrappedHttpClient};
use equs_sdk::vc::oid4vci::CredentialOfferResolver as EqusSdkCredentialOfferResolver;
use equs_sdk::vc::oid4vp::Url;
use std::sync::Arc;

type Result<T> = std::result::Result<T, CredentialOfferResolverError>;

#[derive(uniffi::Error, Debug)]
pub enum CredentialOfferResolverError {
    Constructor(String),
    Resolve(String),
}
impl std::fmt::Display for CredentialOfferResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialOfferResolverError::Constructor(s) => {
                write!(f, "Credential Offer Resolver constructor error: {s}")
            }
            CredentialOfferResolverError::Resolve(s) => {
                write!(f, "Credential Offer Resolver resolve error: {s}")
            }
        }
    }
}

#[derive(uniffi::Object)]
pub struct CredentialOfferResolver(EqusSdkCredentialOfferResolver<WrappedHttpClient>);

#[uniffi::export(async_runtime = "tokio")]
impl CredentialOfferResolver {
    #[uniffi::constructor]
    pub fn new(http_client: Arc<dyn HttpClient>) -> Result<CredentialOfferResolver> {
        let resolver =
            EqusSdkCredentialOfferResolver::with_http_client(WrappedHttpClient::new(http_client));
        Ok(CredentialOfferResolver(resolver))
    }

    pub async fn resolve(&self, offer_uri: String) -> Result<String> {
        self.0
            .resolve(
                Url::parse(&offer_uri)
                    .map_err(|e| CredentialOfferResolverError::Resolve(e.to_string()))?,
            )
            .await
            .map_err(|err| CredentialOfferResolverError::Resolve(err.to_string()))
            .map(|v| {
                serde_json::to_string(&v)
                    .map_err(|e| CredentialOfferResolverError::Resolve(e.to_string()))
            })?
    }
}
