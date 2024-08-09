use oauth2::{
    EmptyExtraTokenFields, HttpRequest, Scope, StandardTokenIntrospectionResponse,
    TokenIntrospectionResponse as TokenIntrospectionResponse_,
};
use oauth2::basic::BasicTokenType;
use oauth2::http::{HeaderValue, Method};
use oauth2::http::header::{ACCEPT, CONTENT_TYPE};
use oid4vci::core::profiles::{CoreProfilesOffer, CoreProfilesRequest, sd_jwt};
use oid4vci::credential::ResponseEnum;
use oid4vci::credential_offer::{CredentialOfferFormat, CredentialOfferGrants, CredentialOfferParameters};
use oid4vci::openidconnect::{IssuerUrl, Nonce};
use oid4vci::openidconnect::http::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::exchange::oid4vc::oid4vci::{CredentialRequest, CredentialResponse, IssuanceMetadata, IssuerMetadata};
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::{Issuer, ProofOfPossession};
use crate::impls::http::{HttpClient, MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON};

const CRED_OFFER_URI: &str = "openid-credential-offer://";

pub type TokenIntrospectionResponse = StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>;

pub struct Oid4VciIssuer
{
    issuer: Box<dyn Issuer>,
    issuer_metadata: IssuerMetadata,
    supported_cred_config_ids: Vec<String>,
    http_client: Box<dyn HttpClient>,
    auth_server_admin_auth_header: Option<HeaderValue>,
    token_validation: bool,
}

impl Oid4VciIssuer {
    pub fn new(
        issuer_metadata: IssuerMetadata,
        issuer: impl Issuer + 'static,
        http_client: impl HttpClient + 'static,
        auth_server_admin_auth_header: Option<HeaderValue>,
        token_validation: bool,
    ) -> Self {
        let supported_cred_config_ids: Vec<String> = issuer_metadata
            .credential_configurations_supported()
            .iter()
            .map(|e| e.0.to_owned())
            .collect();

        Self {
            issuer: Box::new(issuer),
            issuer_metadata,
            supported_cred_config_ids,
            http_client: Box::new(http_client),
            auth_server_admin_auth_header,
            token_validation,
        }
    }

    pub fn metadata(&self) -> IssuerMetadata {
        self.issuer_metadata.clone()
    }

    pub fn create_credential_offer(
        &self,
        configuration_ids: Vec<&str>,
        grants: &CredentialOfferGrants,
    ) -> Result<(CredentialOfferParameters<CoreProfilesOffer>, Url), Error> {
        if configuration_ids.is_empty() {
            return Err(Error::MissingCredentialConfigurationIds);
        }

        for c in &configuration_ids {
            if !self.supported_cred_config_ids.contains(&c.to_string()) {
                return Err(Error::NotSupportedCredentialConfigurationId(
                    c.to_string(),
                ));
            }
        }

        let cred_offer_params: CredentialOfferParameters<CoreProfilesOffer> =
            CredentialOfferParameters::new(
                self.issuer_metadata.credential_issuer().clone(),
                configuration_ids
                    .iter()
                    .map(|c| CredentialOfferFormat::Reference(Scope::new(c.to_string())))
                    .collect(),
                Some(grants.to_owned()),
            );

        let cred_offer =
            serde_json::to_string(&cred_offer_params).map_err(|e| Error::Parse(e))?;

        let mut url = Url::parse(CRED_OFFER_URI)?;
        url.set_query(Some(format!("credential_offer={}", cred_offer).as_str()));

        Ok((cred_offer_params, url))
    }

    pub async fn issue_credential(
        &self,
        cred_request: &CredentialRequest,
        token: &str,
        nonce: Nonce,
        claims: &Value,
    ) -> Result<(CredentialResponse, IssuanceMetadata), Error> {
        let auth_server_url = self.issuer_metadata
            .authorization_servers()
            .and_then(|urls| urls.first());
        if self.token_validation {
            let _ = self.validate_token(&token, auth_server_url).await;
        }
        
        if cred_request.proof().is_none() {
            return Err(Error::ProofVerification(ProofVerificationBody {
                error: "Empty proof".to_string(),
                error_description: "Proof can not be empty, please provide PoP with provided nonce".to_string(),
                c_nonce: Some(nonce),
                c_nonce_expires_in: Some(86440),
            }));
        }

        let cred_def_id = self.resolve_cred_def_id(cred_request)?;
        let cred_req = facade_low_level::CredentialRequest {
            cred_def_id,
            cred_offer_id: None,
            proof: ProofOfPossession::from(cred_request.proof().unwrap()),
            protocol_data: None,
        };
        let result = self.issuer.issue_credential(&cred_req, claims, nonce.secret()).await;

        return match result {
            Err(e) => {
                if let facade_low_level::Error::Proof(e) = e {
                    return Err(Error::ProofVerification(ProofVerificationBody {
                        error: "invalid_proof".to_owned(),
                        error_description: e.to_string(),
                        c_nonce: Some(nonce.to_owned()),
                        c_nonce_expires_in: Some(86440),
                    }));
                }

                Err(Error::Other(e.to_string()))
            }

            Ok((cred, cred_metadata)) => {
                let notification_id = Some(Uuid::new_v4().to_string());
                let resp = CredentialResponse::new(ResponseEnum::Immediate(cred.into()))
                    .set_notification_id(notification_id.clone());

                let issuance_metadata = IssuanceMetadata {
                    core_metadata: cred_metadata,
                    nonce: Some(nonce.to_owned()),
                    notification_id,
                };

                Ok((resp, issuance_metadata))
            }
        };
    }

    fn resolve_cred_def_id(&self, req: &CredentialRequest) -> Result<String, Error> {
        let id = match req.additional_profile_fields() {
            CoreProfilesRequest::SDJWTVC(det) => {
                match det {
                    // TODO: scope=vct only supported by now
                    sd_jwt::Request { vct: Some(id), .. } => id,
                    _ => Err(Error::NotSupportedCredentialConfigurationId("invalid authorization".to_string()))?
                }
            }
            _ => Err(Error::FormatNotSupported)?,
        };

        Ok(id.to_owned())
    }

    pub fn generate_pop_verification_error_and_nonce(&self) -> (Error, Nonce)
    {
        let nonce = Nonce::new(Uuid::new_v4().to_string());

        let err = Error::ProofVerification(ProofVerificationBody {
            error: "Proof of possession is needed".to_string(),
            error_description: "Please provide PoP with provided nonce".to_string(),
            c_nonce: Some(nonce.clone()),
            // TODO: tune via config
            c_nonce_expires_in: Some(86440),
        });

        (err, nonce)
    }

    pub async fn validate_token(
        &self,
        token: &str,
        auth_server_url: Option<&IssuerUrl>,
    ) -> Result<TokenIntrospectionResponse, Error>
    {
        // TODO: refactor: 1. to use Url::join 2. assume different strategies for validation in the future
        let token_introspect_url = if let Some(auth_url) = auth_server_url {
            Url::parse(&format!("{}{}", auth_url.url().to_string(), "protocol/openid-connect/token/introspect"))?
        } else {
            unimplemented!("Validating by jwks.json of auth server is not supported yet")
        };

        let body = Vec::from(format!("token={}", token));
        let (auth_header, auth_value) = (
            AUTHORIZATION,
            // TODO: make optional
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

        let response = self.http_client.async_call(request)
            .await
            .map_err(Error::NetworkRequest)?;
        let token_ifo = serde_json::from_slice::<TokenIntrospectionResponse>(response.body.as_slice())
            .map_err(|e| Error::Parse(e))?;

        if !token_ifo.active() {
            return Err(Error::InActiveToken);
        }

        Ok(token_ifo)
    }
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error
{
    #[error("Missed credential configuration ids")]
    MissingCredentialConfigurationIds,
    #[error("Credential id = {0} is not supported")]
    NotSupportedCredentialConfigurationId(String),
    #[error("Token is expired")]
    InActiveToken,
    #[error("ProofVerification error")]
    ProofVerification(ProofVerificationBody),
    #[error("Url Parse Error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Parsing error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Network Request failed {0}")]
    NetworkRequest(#[from] reqwest::Error),
    #[error("format not supported")]
    FormatNotSupported,
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenInfo {
    active: bool,
    username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofVerificationBody {
    error: String,
    error_description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    c_nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    c_nonce_expires_in: Option<i64>,
}