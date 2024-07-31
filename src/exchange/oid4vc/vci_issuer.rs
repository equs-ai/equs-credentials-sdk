use std::future::Future;

use oauth2::{
    EmptyExtraTokenFields, HttpRequest, HttpResponse, Scope, StandardTokenIntrospectionResponse,
    TokenIntrospectionResponse,
};
use oauth2::basic::BasicTokenType;
use oauth2::http::{HeaderValue, Method};
use oauth2::http::header::{ACCEPT, CONTENT_TYPE};
use oid4vci::core::profiles::CoreProfilesOffer;
use oid4vci::credential::ResponseEnum;
use oid4vci::credential_offer::{CredentialOfferFormat, CredentialOfferGrants, CredentialOfferParameters};
use oid4vci::openidconnect::{IssuerUrl, Nonce};
use oid4vci::openidconnect::http::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::exchange::oid4vc::vci::{CredentialRequest, CredentialResponse, IssuanceMetadata, IssuerMetadata};
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::{Issuer, ProofOfPossession};
use crate::impls::http::{MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON};

const CRED_OFFER_URI: &str = "openid-credential-offer://";

pub struct Oid4VciIssuer
{
    issuer_metadata: IssuerMetadata,
    supported_cred_config_ids: Vec<String>,
    issuer: Box<dyn Issuer>,
    auth_server_admin_auth_header: Option<HeaderValue>,
}

impl Oid4VciIssuer {
    pub fn new(
        issuer_metadata: IssuerMetadata,
        issuer: impl Issuer + 'static,
        auth_server_admin_auth_header: Option<HeaderValue>,
    ) -> Self {
        let supported_cred_config_ids: Vec<String> = issuer_metadata
            .credential_configurations_supported()
            .iter()
            .map(|e| e.0.to_owned())
            .collect();

        Self {
            issuer_metadata,
            supported_cred_config_ids,
            issuer: Box::new(issuer),
            auth_server_admin_auth_header,
        }
    }

    pub fn metadata<IE>(&self) -> Result<Value, IssuanceError<IE>>
    where
        IE: std::error::Error + 'static,
    {
        let metadata_json = serde_json::to_value(self.issuer_metadata.clone())
            .map_err(|e| IssuanceError::Parse(e))?;

        Ok(metadata_json)
    }

    pub fn create_credential_offer<IE>(
        &self,
        configuration_ids: Vec<String>,
        grants: CredentialOfferGrants,
    ) -> Result<(CredentialOfferParameters<CoreProfilesOffer>, Url), IssuanceError<IE>>
    where
        IE: std::error::Error + 'static,
    {
        if configuration_ids.is_empty() {
            return Err(IssuanceError::MissingCredentialConfigurationIds);
        }

        for c in &configuration_ids {
            if !self.supported_cred_config_ids.contains(c) {
                return Err(IssuanceError::NotSupportedCredentialConfigurationId(
                    c.to_owned(),
                ));
            }
        }

        let cred_offer_params: CredentialOfferParameters<CoreProfilesOffer> =
            CredentialOfferParameters::new(
                self.issuer_metadata.credential_issuer().clone(),
                configuration_ids
                    .iter()
                    .map(|c| CredentialOfferFormat::Reference(Scope::new(c.to_owned())))
                    .collect(),
                Some(grants),
            );

        let cred_offer =
            serde_json::to_string(&cred_offer_params).map_err(|e| IssuanceError::Parse(e))?;

        let mut url = Url::parse(CRED_OFFER_URI).map_err(IssuanceError::UrlParse)?;
        url.set_query(Some(format!("credential_offer={}", cred_offer).as_str()));

        Ok((cred_offer_params, url))
    }

    pub async fn issue_credential<C, F, IE>(
        &self,
        cred_request: &CredentialRequest,
        token: &str,
        nonce: Nonce,
        claims: &Value,
        http_client: C,
    ) -> Result<(CredentialResponse, IssuanceMetadata), IssuanceError<IE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output=Result<HttpResponse, IE>>,
        IE: std::error::Error + 'static,
    {
        let auth_server_url = self.issuer_metadata
            .authorization_servers()
            .and_then(|urls| urls.first());
        let _ = self.validate_token(&token, auth_server_url, http_client).await?;

        if let Some(proof) = cred_request.proof() {
            let cred_req = facade_low_level::CredentialRequest {
                cred_def_id: cred_request.credential_identifier.to_owned(),
                cred_offer_id: None,
                proof: ProofOfPossession::from(proof),
                protocol_data: None,
            };
            let result = self.issuer.issue_credential(&cred_req, claims, nonce.secret()).await;

            return match result {
                Err(e) => {
                    if let facade_low_level::Error::Proof(e) = e {
                        return Err(IssuanceError::ProofVerification {
                            error: "invalid_proof".to_owned(),
                            error_description: e.to_string(),
                            c_nonce: Some(nonce),
                            c_nonce_expires_in: None,
                        });
                    }

                    Err(IssuanceError::Other(e.to_string()))
                }

                Ok((cred, cred_metadata)) => {
                    let notification_id = Some(Uuid::new_v4().to_string());
                    let resp = CredentialResponse::new(ResponseEnum::Immediate(cred.into()))
                        .set_notification_id(notification_id.clone());

                    let issuance_metadata = IssuanceMetadata {
                        core_metadata: cred_metadata,
                        nonce: Some(nonce),
                        notification_id,
                    };

                    Ok((resp, issuance_metadata))
                }
            };
        }

        return Err(IssuanceError::ProofVerification {
            error: "Empty proof".to_string(),
            error_description: "Proof can not be empty, please provide PoP with provided nonce".to_string(),
            c_nonce: Some(nonce),
            c_nonce_expires_in: None,
        });
    }

    async fn validate_token<C, F, IE>(
        &self,
        token: &str,
        auth_server_url: Option<&IssuerUrl>,
        http_client: C,
    ) -> Result<
        StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
        IssuanceError<IE>,
    >
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output=Result<HttpResponse, IE>>,
        IE: std::error::Error + 'static,
    {
        let token_introspect_url = if let Some(auth_url) = auth_server_url {
            Url::parse(&format!("{}{}", auth_url.url().to_string(), "token/introspect"))
                .map_err(|e| IssuanceError::UrlParse(e))?
        } else {
            unimplemented!("Validating by jwks.json of auth server is not supported yet")
        };

        let body = Vec::from(format!("token={}", token));
        let (auth_header, auth_value) = (
            AUTHORIZATION,
            self.auth_server_admin_auth_header.to_owned().unwrap(),
        );

        let request = HttpRequest {
            url: token_introspect_url,
            method: Method::POST,
            headers: vec![
                (
                    CONTENT_TYPE,
                    HeaderValue::from_static(MIME_TYPE_FORM_URLENCODED),
                ),
                (ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON)),
                (auth_header, auth_value),
            ]
                .into_iter()
                .collect(),
            body,
        };

        let response = http_client(request)
            .await
            .map_err(IssuanceError::NetworkRequest)?;
        let token_ifo = serde_json::from_slice::<
            StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
        >(response.body.as_slice())
            .map_err(|e| IssuanceError::Parse(e))?;

        if !token_ifo.active() {
            return Err(IssuanceError::InActiveToken());
        }

        Ok(token_ifo)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IssuanceError<IE>
where
    IE: std::error::Error + 'static,
{
    #[error("Missed credential configuration ids")]
    MissingCredentialConfigurationIds,
    #[error("Credential id = {0} is not supported")]
    NotSupportedCredentialConfigurationId(String),
    #[error("Token is expired")]
    InActiveToken(),
    #[error("ProofVerification error")]
    ProofVerification {
        error: String,
        error_description: String,
        c_nonce: Option<Nonce>,
        c_nonce_expires_in: Option<i64>,
    },
    #[error("Url Parse Error: {0}")]
    UrlParse(#[source] url::ParseError),
    #[error("Parsing error: {0}")]
    Parse(#[source] serde_json::Error),
    #[error("Network Request failed {0}")]
    NetworkRequest(#[source] IE),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenInfo {
    active: bool,
    username: Option<String>,
}
