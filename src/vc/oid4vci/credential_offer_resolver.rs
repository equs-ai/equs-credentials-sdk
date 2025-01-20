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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;
    use crate::utils::http::test::mock_http_once;
    use crate::vc::oid4vci::tests::fixtures::{
        sample_offer_with_auth_code_grant, sample_offer_with_pre_auth_code_grant,
    };
    use crate::vc::oid4vci::PreAuthorizedCode;
    use oauth2::http::{Method, StatusCode};
    use oid4vci::types::{CredentialConfigurationId, IssuerState};
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case::offer_by_reference_with_auth_code_grant_success(
        "openid-credential-offer://?credential_offer_uri=http://localhost:8088/credential_offer",
        sample_offer_with_auth_code_grant(None)
    )]
    #[case::offer_by_reference_with_pre_auth_code_grant_success(
        "openid-credential-offer://?credential_offer_uri=http://localhost:8088/credential_offer",
        sample_offer_with_pre_auth_code_grant("pre_auth_code")
    )]
    #[tokio::test]
    async fn resolve_offer_by_reference_works_correctly(
        #[case] offer_uri: &str,
        #[case] offer_response: CredentialOfferParams,
    ) {
        let mut http_client = MockHttpClient::new();
        mock_http_once(
            &mut http_client,
            Method::GET,
            Url::parse("http://localhost:8088/credential_offer").unwrap(),
            offer_response.clone(),
            StatusCode::OK,
        );

        let resolver = CredentialOfferResolver::with_http_client(http_client);
        let resolved_offer = resolver
            .resolve(Url::parse(offer_uri).unwrap())
            .await
            .unwrap();
        assert_eq!(json!(resolved_offer), json!(offer_response));
    }

    #[rstest]
    #[case::offer_with_auth_code_grant_success(
        "{%22credential_issuer%22:%22http://localhost:8088%22,%22credential_configuration_ids%22:[%22SD_JWT_cred_1%22,%22JSON_LDP_cred_2%22],%22grants%22:{%22authorization_code%22:{%22issuer_state%22:%22state%22,%22authorization_server%22:%22http://localhost:8088%22}}}",
        "auth_code"
    )]
    #[case::offer_with_pre_auth_code_grant_success(
        "{%22credential_issuer%22:%22http://localhost:8088%22,%22credential_configuration_ids%22:[%22SD_JWT_cred_1%22,%22JSON_LDP_cred_2%22],%22grants%22:{%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:{%22pre-authorized_code%22:%22code%22,%22tx_code%22:null,%22interval%22:null,%22authorization_server%22:%22http://localhost:8088%22}}}",
        "pre-auth_code",
    )]
    #[tokio::test]
    async fn resolve_offer_by_value_works_correctly(
        #[case] encoded_offer: &str,
        #[case] flow: &str,
    ) {
        let resolver = CredentialOfferResolver::new().unwrap();
        let resolved_offer = resolver
            .resolve(
                Url::parse(&format!(
                    "openid-credential-offer://?credential_offer={encoded_offer}"
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        let grant = resolved_offer.grants.unwrap();
        match flow {
            "auth_code" => {
                let grant = grant.authorization_code.unwrap();
                assert_eq!(
                    grant.issuer_state(),
                    Some(&IssuerState::new("state".to_string())),
                );
                assert_eq!(
                    grant.authorization_server().unwrap().to_string(),
                    "http://localhost:8088".to_string()
                )
            }
            _ => {
                let grant = grant.pre_authorized_code.unwrap();

                assert_eq!(
                    grant.pre_authorized_code(),
                    &PreAuthorizedCode::new("code".to_string())
                );
                assert_eq!(
                    grant.authorization_server().unwrap().to_string(),
                    "http://localhost:8088".to_string()
                )
            }
        }

        assert_eq!(
            resolved_offer.credential_issuer.to_string(),
            "http://localhost:8088".to_string()
        );
        assert_eq!(
            resolved_offer.credential_configuration_ids,
            vec![
                CredentialConfigurationId::new("SD_JWT_cred_1".to_string()),
                CredentialConfigurationId::new("JSON_LDP_cred_2".to_string())
            ]
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "invalid type: string \"{}\", expected struct CredentialOfferParameters"
    )]
    async fn resolve_offer_by_reference_fails_when_response_contains_invalid_data() {
        let mut http_client = MockHttpClient::new();
        mock_http_once(
            &mut http_client,
            Method::GET,
            Url::parse("http://localhost:8088/credential_offer").unwrap(),
            json!("{}"),
            StatusCode::OK,
        );

        let resolver = CredentialOfferResolver::with_http_client(http_client);
        let resolved_offer = resolver
            .resolve(Url::parse("openid-credential-offer://?credential_offer_uri=http://localhost:8088/credential_offer").unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "RelativeUrlWithoutBase")]
    async fn resolve_offer_by_reference_fails_when_offer_uri_is_invalid() {
        let resolver = CredentialOfferResolver::new().unwrap();
        let resolved_offer = resolver
            .resolve(
                Url::parse(
                    "invalid_scheme://?credential_offer_uri=http://localhost:8088/credential_offer",
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }
}
