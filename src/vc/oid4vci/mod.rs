use async_trait::async_trait;
use oid4vci::core::profiles::CoreProfilesOffer;
use oid4vci::credential::{ProofVerificationErrorBody, RequestError};
use oid4vci::openidconnect;
use url::Url;

use crate::{storage, vault, vc};
use crate::vc::{Claims, Credential, CredentialMetadata};

mod issuer;
mod holder;
mod introspect;
mod metadata;

// Data types
pub type IssuerMetadata = oid4vci::core::metadata::IssuerMetadata;
pub type CredentialOfferGrants = oid4vci::credential_offer::CredentialOfferGrants;
pub type CredentialOfferParams = oid4vci::credential_offer::CredentialOfferParameters<CoreProfilesOffer>;
pub type CredentialRequest = oid4vci::core::credential::Request;
pub type CredentialResponse = oid4vci::core::credential::Response;
pub type TokenResponse = oid4vci::token::Response;

#[derive(Debug, Clone)]
pub enum CredentialResult {
    Deferred { transaction_id: String },
    Credential { credential: Credential, notification_id: Option<String> },
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum IssuerError
{
    #[error("Missed credential configuration ids")]
    MissingCredentialConfigurationIds,
    #[error("Credential id = {0} is not supported")]
    NotSupportedCredentialConfigurationId(String),
    #[error("Invalid token: {0}")]
    InvalidToken(#[from] introspect::Error),
    #[error("Invalid proof")]
    InvalidProof(ProofVerificationErrorBody),
    #[error("Url Parse Error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Parsing error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Network Request failed {0}")]
    Storage(#[from] storage::Error),
    #[error("format not supported")]
    FormatNotSupported,
    #[error("VC error: {0}")]
    VC(#[from] vc::core::Error),
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum HolderError {
    // oid4vci
    #[error(transparent)]
    Request(#[from] RequestError<reqwest::Error>),
    #[error(transparent)]
    Client(#[from] oid4vci::client::Error),

    // openid connect/ouath
    #[error(transparent)]
    Discovery(#[from] openidconnect::DiscoveryError<reqwest::Error>),
    #[error(transparent)]
    Token(#[from] oauth2::RequestTokenError<reqwest::Error, oid4vci::token::Error>),

    // Low-level
    #[error(transparent)]
    VC(#[from] vc::core::Error),
    #[error(transparent)]
    Vault(#[from] vault::Error),

    #[error("proof not supported")]
    ProofNotSupported,
    #[error("format not supported")]
    FormatNotSupported,
    #[error("CSRF failure")]
    CsrfFailure,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("nonce missed")]
    NonceMissed,
    #[error("not supported")]
    NotSupported,
    #[error("cred def not found: {0}")]
    CredDefNotFound(String),

    // Common
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

// API

#[async_trait]
pub trait Issuer {
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants, // grant type (auth code, pre-auth code), etc.
    ) -> Result<(CredentialOfferParams, Url), IssuerError>;

    async fn issue_credential(
        &self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &Claims,
    ) -> Result<CredentialResponse, IssuerError>;
}

#[async_trait]
pub trait Holder {
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    async fn authz_code_flow_with_scope(
        &self,
        cred_def_id: String,
        authorization_callback: impl FnOnce(Url) -> String + Send,
    ) -> Result<TokenResponse, HolderError>;

    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> Result<TokenResponse, HolderError>;

    async fn request_credential(
        &self,
        token_response: &TokenResponse,
        cred_def_id: &str,
    ) -> Result<CredentialResult, HolderError>;

    async fn store_credential(
        &self,
        credential: &Credential,
        // TODO: update after vault::find and CredMetadata refactoring
        credential_metadata: &CredentialMetadata,
    ) -> Result<(), HolderError>;
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures::executor;
    use oauth2::{HttpRequest, HttpResponse};
    use oauth2::http::{Method, StatusCode};
    use oid4vci::core::credential_offer::CredentialOffer;
    use oid4vci::core::metadata::IssuerMetadata;
    use oid4vci::credential_offer::AuthorizationCodeGrant;
    use oid4vci::metadata::AuthorizationMetadata;
    use oid4vci::openidconnect::Nonce;
    use serde_json::json;
    use url::Url;

    use crate::{kms, vc};
    use crate::crypto::Key;
    use crate::did::didkey::DIDKey;
    use crate::did::DIDURL;
    use crate::kms::Kms;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::storage::InMemStorage;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::{mock_http, mock_http_fn, mock_http_once, mock_static_ctx, MockHttpClient};
    use crate::vc::core::{HolderMetadata, KeyMetadata};
    use crate::vc::oid4vci::{CredentialOfferGrants, CredentialOfferParams, Holder, issuer, Issuer};
    use crate::vc::oid4vci::holder::HolderService;
    use crate::vc::oid4vci::introspect::Introspect;
    use crate::vc::oid4vci::issuer::{IssuerService, TokenValidation};
    use crate::vc::oid4vci::metadata::convert_metadata;

    // FIXTURES
    const ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ";
    const CRED_DEF_ID: &str = "SD_JWT_cred";

    #[tokio::test]
    async fn e2e() {
        // Setting up mocks and fixtures
        let iss_url_str = "https://issuer-backend.com";
        let authz_url_str = "https://authz-backend.com";

        let issuer_metadata = sample_issuer_metadata(iss_url_str, authz_url_str);
        let authorization_metadata = sample_authorization_metadata(authz_url_str);

        let mut http_mock = MockHttpClient::new();
        let mut http_mock_iss = MockHttpClient::new();

        let iss_url = Url::parse(iss_url_str).unwrap();
        let authz_url = Url::parse(authz_url_str).unwrap();

        let ctx = MockHttpClient::static_async_context();
        mock_static_ctx(
            &ctx,
            Method::GET,
            iss_url.join("/.well-known/openid-credential-issuer").unwrap(),
            issuer_metadata.clone(),
            StatusCode::OK,
        );

        mock_static_ctx(
            &ctx,
            Method::GET,
            authz_url.join("/.well-known/openid-configuration").unwrap(),
            authorization_metadata.clone(),
            StatusCode::OK,
        );

        let authz_code = Nonce::new_random();
        let req_uri_code = Nonce::new_random();

        mock_http_once(
            &mut http_mock,
            Method::POST,
            authz_url.join("/par/request").unwrap(),
            json!({
                "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + req_uri_code.clone().secret(),
                "expires_in": 86400,
             }),
            StatusCode::CREATED,
        );

        mock_http_once(
            &mut http_mock,
            Method::POST,
            authz_url.join("/token").unwrap(),
            json!({
                "access_token": ACCESS_TOKEN,
                "token_type": "bearer",
                "expires_in": 86400,
                "authorization_details": [
                    {
                        "type": "openid_credential",
                        "format": "vc+sd-jwt",
                        "vct": CRED_DEF_ID,
                    }
                ]
            }),
            StatusCode::OK,
        );

        mock_http(
            &mut http_mock_iss,
            Method::POST,
            authz_url.join("/token/introspect").unwrap(),
            json!({
                  "active": true,
            }),
            StatusCode::OK,
            2.into(),
        );

        // 1. Creating issuer from issuer metadata
        let introspect_ep = authz_url.join("/token/introspect").unwrap();
        let issuer = oid4vci_issuer(issuer_metadata.clone(), http_mock_iss, introspect_ep).await;

        // 2. Creating offer
        let (offer, _) = issuer.create_credential_offer(
            vec![CRED_DEF_ID],
            &CredentialOfferGrants {
                authorization_code: Some(AuthorizationCodeGrant { issuer_state: None }),
                pre_authorized_code: None,
            },
        ).unwrap();

        mock_http_fn(
            &mut http_mock,
            Method::POST,
            iss_url.join("/credential").unwrap(),
            move |req| {
                // 6.2 Issuer will issue credentials
                let fut = credential_endpoint(&issuer, req);
                let result = executor::block_on(fut);
                Ok(result)
            },
            2.into(),
        );

        // 3.1 Creating holder from offer
        let holder = oid4vci_holder(offer, http_mock).await;

        // 4. Holder has issuer metadata
        assert_eq!(&holder.get_issuer_metadata(), &issuer_metadata);

        // 5. Holder authorizes
        let token_response = holder.authz_code_flow_with_scope(
            CRED_DEF_ID.into(),
            |url| {
                println!("Url {}", url);

                assert!(url.to_string().starts_with(&authz_url.to_string()));
                assert!(url.query().unwrap().contains(req_uri_code.secret()));

                authz_code.secret().to_owned()
            },
        ).await.unwrap();

        println!("Token response {:?}", token_response);

        // 6.1 Holder requests credentials
        let credential = holder.request_credential(
            &token_response.clone(),
            CRED_DEF_ID,
        ).await.unwrap();

        println!("Credential: {:?}", credential);
    }

    async fn credential_endpoint(issuer: &impl Issuer, req: HttpRequest) -> HttpResponse {
        let cred_req = serde_json::from_slice(req.body.as_slice()).unwrap();
        let token = req.headers.get("Authorization").unwrap();
        let token = token.to_str().unwrap()
            .strip_prefix("Bearer ").unwrap()
            .to_string();

        let claims = json!( {
                        "vct": "SD_JWT_cred",
                        "type": ["SD_JWT_cred"],
                        "given_name": "John",
                        "family_name": "Doe",
                        "dob": "09/09/1989",
                    });

        let result = issuer.issue_credential(
            &cred_req,
            &token,
            &claims,
        ).await;

        let response = match result {
            Ok(cred_resp) => HttpResponse {
                status_code: StatusCode::OK,
                headers: Default::default(),
                body: serde_json::to_vec(&cred_resp).unwrap(),
            },
            Err(issuer::Error::InvalidProof(b)) => HttpResponse {
                status_code: StatusCode::BAD_REQUEST,
                headers: Default::default(),
                body: serde_json::to_vec(&b).unwrap(),
            },
            _ => panic!(),
        };

        response
    }

    async fn oid4vci_holder(credential_offer: CredentialOfferParams, http_client: MockHttpClient) -> impl Holder + Sized {
        let inner = holder().await;
        HolderService::from_credential_offer(
            inner,
            http_client,
            &CredentialOffer::Value { credential_offer },
            "wallet-dev".to_string(),
            "urn:ietf:wg:oauth:2.0:oob".to_string(),
        ).await.unwrap()
    }

    async fn oid4vci_issuer(metadata: IssuerMetadata, http_client: MockHttpClient, introspect_ep: Url) -> impl Issuer + Sized {
        let inner = issuer(&metadata).await;
        let storage = InMemStorage::new();
        let introspect = Introspect::new(http_client, introspect_ep, None);
        IssuerService::new(
            metadata,
            inner,
            storage,
            TokenValidation::Introspect(introspect),
        )
    }

    async fn holder() -> impl vc::core::Holder {
        // Initialization
        println!("Holder creating...");

        let kms = LocalKms::new();
        let didkey = DIDKey::new();
        let vault = InMemVault::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        vc::core::HolderService::new(kms, vault, HolderMetadata {
            client_id: "wallet-dev".into(),
            key_metadata: KeyMetadata {
                did_url: did_url.to_string(),
                kid: kid.clone(),
            },
        })
    }

    async fn issuer(metadata: &IssuerMetadata) -> impl vc::core::Issuer {
        println!("Issuer creating...");

        let kms = LocalKms::new();
        let didkey = DIDKey::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        let key_metadata = KeyMetadata {
            did_url: did_url.to_string(),
            kid: kid.clone(),
        };

        let converted = convert_metadata(metadata, key_metadata);

        vc::core::IssuerService::new(kms, converted)
    }

    fn sample_issuer_metadata(iss_url: &str, authz_url: &str) -> IssuerMetadata {
        let metadata = serde_json::from_value(json!(
            {
              "credential_issuer": iss_url,
              "authorization_servers": [authz_url],
              "credential_endpoint": iss_url.to_owned()+"/credential",
              "credential_configurations_supported": {
                "SD_JWT_cred": {
                  "format": "vc+sd-jwt",
                  "scope": "SD_JWT_cred",
                  "cryptographic_binding_methods_supported": [
                    "jwk"
                  ],
                  "credential_signing_alg_values_supported": [
                    "ES256"
                  ],
                  "proof_types_supported": {
                    "jwt": {
                      "proof_signing_alg_values_supported": [
                        "ES256"
                      ]
                    }
                  },
                  "vct": "SD_JWT_cred",
                  "credential_definition": {
                      "type": "SD_JWT_cred",
                      "claims": {
                        "given_name": {},
                        "family_name": {}
                      }
                    }
                }
              }
            }
        ));

        metadata.unwrap()
    }

    fn sample_authorization_metadata(authz_url: &str) -> AuthorizationMetadata {
        let metadata = serde_json::from_value(json!(
            {
                "issuer": authz_url,
                "authorization_endpoint": authz_url.to_owned()+"/auth",
                "token_endpoint": authz_url.to_owned()+"/token",
                "introspection_endpoint": authz_url.to_owned()+"/protocol/openid-connect/token/introspect",
                "jwks_uri": authz_url.to_owned()+"/cert",
                "grant_types_supported": [
                    "authorization_code",
                ],
                "response_types_supported": [
                    "code",
                    "token",
                ],
                "subject_types_supported": [
                    "public",
                ],
                "id_token_signing_alg_values_supported": [
                    "ES256",
                ],
                "pushed_authorization_request_endpoint": authz_url.to_owned()+"/par/request",
            }
        ));

        metadata.unwrap()
    }
}