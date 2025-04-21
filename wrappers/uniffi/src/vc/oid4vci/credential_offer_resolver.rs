use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::reqwest::ReqwestClient;
use agent_sdk::vc::oid4vci::CredentialOfferResolver as ASDKCredentialOfferResolver;
use agent_sdk::vc::oid4vp::Url;

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
pub struct CredentialOfferResolver(ASDKCredentialOfferResolver<ReqwestClient>);

#[uniffi::export(async_runtime = "tokio")]
impl CredentialOfferResolver {
    #[uniffi::constructor]
    pub fn new() -> Result<CredentialOfferResolver> {
        #[allow(unused_assignments)]
        let mut resolver = ASDKCredentialOfferResolver::new()
            .map_err(|e| CredentialOfferResolverError::Constructor(e.to_string()))?;

        #[cfg(debug_assertions)]
        {
            resolver = ASDKCredentialOfferResolver::with_http_client(
                ReqwestClientBuilder::new()
                    .insecure()
                    .build()
                    .map_err(|e| CredentialOfferResolverError::Constructor(e.to_string()))?,
            )
        }

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
