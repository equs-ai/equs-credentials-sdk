use async_trait::async_trait;
use oid4vci::core::profiles::CoreProfilesOffer;
use oid4vci::credential::RequestError;
use oid4vci::openidconnect::DiscoveryError;
use serde::{Deserialize, Serialize};

use crate::vc::oid4vci::Error::{Internal, Protocol};
use crate::vc::oid4vci::InternalError::{ClaimNamesValidation, Network, Other, Unhandled, Url, VC};
use crate::vc::{Claims, Credential, CredentialMetadata};
use crate::{storage, vault, vc};

pub(crate) mod issuer;
pub(crate) mod holder;
mod token_validation;
mod metadata;

mod builder;
pub use builder::HolderBuilder;
pub use builder::IssuerBuilder;

// Data types
pub type IssuerMetadata = oid4vci::core::metadata::IssuerMetadata;
pub type AuthorizationMetadata = oid4vci::metadata::AuthorizationMetadata;
pub type CredentialOffer = oid4vci::credential_offer::CredentialOffer<CoreProfilesOffer>;
pub type CredentialOfferGrants = oid4vci::credential_offer::CredentialOfferGrants;
pub type CredentialOfferParams = oid4vci::credential_offer::CredentialOfferParameters<CoreProfilesOffer>;
pub type CredentialRequest = oid4vci::core::credential::Request;
pub type CredentialResponse = oid4vci::core::credential::Response;
pub type TokenResponse = oid4vci::token::Response;
pub type AuthorizationCodeGrant = oid4vci::credential_offer::AuthorizationCodeGrant;
pub type ErrorType = oid4vci::credential::ErrorType;
pub type Nonce = oid4vci::openidconnect::Nonce;

/// A result of the Credential issuance handled by `Holder`
///
/// [Credential] contains issued `Credential`.
///
/// *NOTE*: `deferred` flow and `notifications` currently are not supported.
#[derive(Debug, Clone)]
pub enum CredentialResult {
    Deferred { transaction_id: String },
    Credential { credential: Credential, notification_id: Option<String> },
}

/// A session with state managed during the issuance.
///
/// Contains [NonceData].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuanceSession {
    nonce: Option<NonceData>,
    notification_id: Option<String>,
    transaction_id: Option<String>,
}

impl Default for IssuanceSession {
    fn default() -> Self {
        Self {
            nonce: None,
            notification_id: None,
            transaction_id: None,
        }
    }
}

/// A struct containing nonce and related data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceData {
    nonce: Nonce,
    expires_in: Option<i64>,
    created: Option<time::OffsetDateTime>,
}

/// `oid4vci` API common error.
///
/// Used by `oid4vci` `Issuer` and `Holder`.
///
/// * [Protocol] encapsulates all expected [ProtocolErrorResponse] errors specific to the standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// * [Internal] error contains all unexpected errors.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum Error
{
    #[error(transparent)]
    Internal(#[from] InternalError),
    #[error(transparent)]
    Protocol(#[from] ProtocolErrorResponse),
}

/// A protocol-specific `oid4vci` error response.
///
/// Those errors are defined in the standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// Should be treated like 4xx errors.
///
/// # Nonce
///
/// `Holder`s MUST use `c_nonce` and `c_nonce_expires_in` for subsequent requests if they're returned.
#[derive(Clone, thiserror::Error, Debug, Deserialize, Serialize)]
#[error("Protocol error: type = {:?}, description: {:?}", error, error_description)]
pub struct ProtocolErrorResponse {
    error: ErrorType,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    c_nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    c_nonce_expires_in: Option<i64>,
}

impl ProtocolErrorResponse {
    pub fn new(error: ErrorType, description: &str) -> Self {
        Self {
            error,
            error_description: Some(description.to_owned()),
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    }

    pub fn new_with_nonce(
        error: ErrorType,
        description: &str,
        nonce: Nonce,
        nonce_expires_in: Option<i64>,
    ) -> Self {
        Self {
            error,
            error_description: Some(description.to_owned()),
            c_nonce: Some(nonce),
            c_nonce_expires_in: nonce_expires_in,
        }
    }
}

/// An `oid4vci` internal error.
///
/// Internal errors unspecified by the protocol.
///
/// Should be treated like 5xx errors.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum InternalError
{
    #[error("cred def not found: {0}")]
    CredDefNotFound(String),
    #[error("Claim names validation error: {0}")]
    ClaimNamesValidation(String),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    #[error(transparent)]
    Storage(#[from] storage::Error),
    #[error(transparent)]
    VC(#[from] vc::core::Error),
    #[error(transparent)]
    Vault(#[from] vault::Error),
    #[error(transparent)]
    Network(#[from] reqwest::Error),
    #[error(transparent)]
    Discovery(#[from] DiscoveryError<reqwest::Error>),
    #[error("other error: {0}")]
    Other(String),
    #[error("unhandled error: {0}")]
    Unhandled(String),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Internal(Network(err))
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Self {
        Internal(Url(err))
    }
}

impl From<vc::core::Error> for Error {
    fn from(err: vc::core::Error) -> Self {
        Internal(VC(err))
    }
}

impl From<RequestError<reqwest::Error>> for Error {
    fn from(err: RequestError<reqwest::Error>) -> Self {
        match err {
            RequestError::ClaimsVerification(e) => { Internal(ClaimNamesValidation(e.to_string())) }
            RequestError::Request(e) => { Internal(Network(e)) }
            RequestError::Response(_, body, _) => {
                let err = match serde_json::from_slice::<ProtocolErrorResponse>(body.as_slice()) {
                    Ok(ptr_err) => Protocol(ptr_err),
                    _ => {
                        match serde_json::from_slice::<String>(body.as_slice()) {
                            Ok(err) => Internal(Unhandled(err)),
                            _ => Internal(Other("can not parse credential response error".to_string()))
                        }
                    }
                };

                err
            }
            RequestError::ProofVerification(b) => {
                let err = match (b.c_nonce, b.c_nonce_expires_in) {
                    (Some(nonce), Some(expires_in)) =>
                        ProtocolErrorResponse::new_with_nonce(
                            ErrorType::InvalidProof,
                            &b.error_description,
                            nonce,
                            Some(expires_in),
                        ),
                    _ => ProtocolErrorResponse::new(ErrorType::InvalidProof, &b.error_description)
                };

                Protocol(err)
            }
            RequestError::Parse(e) => { Internal(Other(e.to_string())) }
            RequestError::Other(e) => { Internal(Other(e)) }
            _ => { Internal(Unhandled("unhandled error".to_owned())) }
        }
    }
}

/// `Result` alias for `oid4vci`-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// An async `oid4vci` `Issuer` API.
///
/// Supports issuance flow according to the `oid4vci` standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// # Supported features
///
/// * exposing metadata
/// * credential issuance (immediate)
/// * credential offer generation
///
/// # Implementation
///
/// Use [IssuerBuilder] to instantiate a service.
/// Existing implementation of the API is not exposed.
#[async_trait]
pub trait Issuer: Send + Sync {
    /// Returns the `Metadata` of the `Issuer`.
    ///
    /// # Returns
    ///
    /// An `IssuerMetadata`.
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    /// Create a `CredentialOffer` for multiple `CredDef` ids.
    ///
    /// Generated `CredentialOffer` matches provided `CredentialDefinition`s
    /// and should be later used by `Holder` to create a corresponding `CredentialRequest`.
    ///
    /// # Arguments
    ///
    /// * `cred_def_ids` - a vector with `CredentialDefinition` IDs.
    /// * `grants` - grant types of the generated `Offer`, contains which flow is defined - pre-authorized/authorized.
    ///
    /// # Returns
    ///
    /// A `CredentialOfferParams` and the corresponding Url to be shared with `Holder` on success.
    ///
    /// # Errors
    ///
    /// * [Protocol] - expected protocol-specific error.
    ///     * [ErrorType::InvalidRequest]
    ///     * [ErrorType::UnsupportedCredentialType]
    /// * [InternalError::Parse] - fails to parse the payload.
    /// * [InternalError::Url] - fails to parse `Url`.
    fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants, // grant type (auth code, pre-auth code), etc.
    ) -> Result<(CredentialOfferParams, url::Url)>;

    /// Issue a `Credential` based on the provided `CredentialRequest`.
    ///
    /// `CredentialRequest` should match some existing `CredentialDefinition` defined in the `IssuerMetadata`.
    /// `Proof of Possession` is mandatory.
    ///
    /// This method should be used for `Immediate` credential issuance.
    /// `Deferred` option is not supported yet.
    ///
    /// # Arguments
    ///
    /// * `cred_request` - a `CredentialRequest` used for `Credential` generation.
    /// * `token` - an access token used for authorization.
    /// * `claims` - claims to include into the `Credential`.
    /// * `session` - a `&mut` session object which contains `Nonce` and other state.
    /// Will be updated if the state was changed.
    ///
    /// # Returns
    ///
    /// A `CredentialResponse` (containing serialized `Credential`) on success.
    ///
    /// # Errors
    ///
    /// * [Protocol] - expected protocol-specific error.
    ///     * [ErrorType::InvalidRequest]
    ///     * [ErrorType::InvalidProof]
    ///     * [ErrorType::InvalidToken]
    ///     * [ErrorType::UnsupportedCredentialType]
    ///     * [ErrorType::UnsupportedCredentialFormat]
    /// * [InternalError::VC] - `vc::core` error during `Credential` signing or `Proof` validation.
    async fn issue_credential(
        &self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &Claims,
        session: &mut IssuanceSession,
    ) -> Result<CredentialResponse>;
}

/// An async `oid4vci` `Holder` API.
///
/// Supports authorization and issuance flow according to the `oid4vci` standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// # Supported features
///
/// * retrieving metadata
/// * credential issuance (immediate)
/// * authorized code flow (using Pushed Authorization Request)
///
/// *NOTE*: Pre-authorized code flow is not yet supported.
///
/// # Implementation
///
/// Use [HolderBuilder] to instantiate a service.
/// Existing implementation of the API is not exposed.
#[async_trait]
pub trait Holder: Send + Sync {
    /// Returns the `Metadata` of the `Issuer`.
    ///
    /// # Returns
    ///
    /// An `IssuerMetadata`.
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    /// Run Authorization Code Flow to authorize the `Holder`.
    ///
    /// Leverages Pushed Authorization Request endpoint, PKCE and CSRF tokens.
    ///
    /// Currently, only `scope`=`cred_def_id` is supported.
    ///
    /// # Arguments
    ///
    /// * `cred_def_id` - a `CredentialDefinition` ID.
    /// * `authorization_callback` - a callback to retrieve an authorization code by the given `auth_url`.
    /// Requires application layer interaction.
    ///
    /// # Returns
    ///
    /// A `TokenResponse` with a valid token to be used for issuing a `Credential` on success.
    ///
    /// # Errors
    ///
    /// * [Protocol] - expected protocol-specific error.
    ///     * [ErrorType::InvalidRequest]
    /// * [InternalError::Network] - fails to make a call to the `Issuer`.
    async fn authz_code_flow_with_scope(
        &self,
        cred_def_id: String,
        authorization_callback: impl FnOnce(url::Url) -> String + Send,
    ) -> Result<TokenResponse>;

    /// Run Pre-authorized Code Flow to authorize the `Holder`.
    ///
    /// *NOTE*: **not implemented yet**.
    ///
    /// # Arguments
    ///
    /// * `pre_authorized_code` - a pre-authorization code.
    /// * `tx_code` - a transaction code.
    /// * `cred_def_id` - a `CredentialDefinition` ID.
    ///
    /// # Returns
    ///
    /// A `TokenResponse` with a valid token to be used for issuing a `Credential` on success.
    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> Result<TokenResponse>;

    /// Request a `Credential` for the provided `CredentialDefinition`.
    ///
    /// Makes a call to an Issue Credential endpoint under the hood.
    ///
    /// If no nonce were provided with `token_response`
    /// service will make an empty request to re-request nonce from the `Issuer` automatically.
    ///
    /// Always generates and provides a `Proof of Possession` in the request.
    ///
    /// After getting the `Credential`, verifies it against the signature by resolving the issuer's DID.
    /// # Arguments
    ///
    /// * `token_response` - an authz response containing valid access token. May contain nonce.
    /// * `cred_def_id` - a `CredentialDefinition` ID.
    ///
    /// # Returns
    ///
    /// A `CredentialResult` (Immediate or Deferred) on success.
    ///
    /// # Errors
    ///
    /// * [Protocol] - expected protocol-specific error.
    ///     * [ErrorType::InvalidRequest]
    ///     * [ErrorType::UnsupportedCredentialType]
    ///     * [ErrorType::UnsupportedCredentialFormat]
    /// * [InternalError::Parse] - fails to parse the payload.
    /// * [InternalError::Network] - fails to make a call to the `Issuer`.
    /// * [InternalError::VC] - `vc::core` error during `Proof` generation or credential signature verification.
    async fn request_credential(
        &self,
        token_response: &TokenResponse,
        cred_def_id: &str,
    ) -> Result<CredentialResult>;

    /// Store a `Credential`.
    ///
    /// This method will store the `credential` into the `Vault` under the hood.
    ///
    /// # Arguments
    ///
    /// * `credential` - a `Credential` to save.
    /// * `credential_metadata` - the corresponding `CredentialMetadata`.
    ///
    /// # Errors
    ///
    /// * [InternalError::Vault] - error with [vault::Vault].
    async fn store_credential(
        &self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use futures::executor;
    use oauth2::http::{Method, StatusCode};
    use oauth2::{HttpRequest, HttpResponse};
    use oid4vci::core::credential_offer::CredentialOffer;
    use oid4vci::core::metadata::IssuerMetadata;
    use oid4vci::credential_offer::AuthorizationCodeGrant;
    use oid4vci::metadata::AuthorizationMetadata;
    use oid4vci::openidconnect::Nonce;
    use serde_json::json;
    use std::str::FromStr;
    use url::Url;

    use crate::crypto::Key;
    use crate::did::didkey::DIDKey;
    use crate::did::DIDURL;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::Kms;
    use crate::utils::http::{mock_http, mock_http_fn, mock_http_once, mock_static_ctx, MockHttpClient};
    use crate::vc::core::{HolderMetadata, KeyMetadata};
    use crate::vc::oid4vci::holder::HolderService;
    use crate::vc::oid4vci::issuer::{IssuerService, TokenValidation};
    use crate::vc::oid4vci::metadata::convert_metadata;
    use crate::vc::oid4vci::token_validation::Introspect;
    use crate::vc::oid4vci::{issuer, CredentialOfferGrants, CredentialOfferParams, Holder, IssuanceSession, Issuer};
    use crate::{kms, vc};

    // FIXTURES
    const ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA";
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

        let mut session = IssuanceSession::default();
        mock_http_fn(
            &mut http_mock,
            Method::POST,
            iss_url.join("/credential").unwrap(),
            move |req| {
                // 6.2 Issuer will issue credentials
                let fut = credential_endpoint(&issuer, req, &mut session);
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

    async fn credential_endpoint(issuer: &impl Issuer, req: HttpRequest, session: &mut IssuanceSession) -> HttpResponse {
        let cred_req = serde_json::from_slice(req.body.as_slice()).unwrap();
        let token = req.headers.get("Authorization").unwrap();
        let token = token.to_str().unwrap()
            .strip_prefix("Bearer ").unwrap()
            .to_string();

        let claims = json!( {
                        "vct": "SD_JWT_cred",
                        "given_name": "John",
                        "family_name": "Doe",
                        "dob": "09/09/1989",
                    });

        let result = issuer.issue_credential(
            &cred_req,
            &token,
            &claims,
            session,
        ).await;

        let response = match result {
            Ok(cred_resp) => HttpResponse {
                status_code: StatusCode::OK,
                headers: Default::default(),
                body: serde_json::to_vec(&cred_resp).unwrap(),
            },
            Err(issuer::Error::Protocol(b)) => {
                return HttpResponse {
                    status_code: StatusCode::BAD_REQUEST,
                    headers: Default::default(),
                    body: serde_json::to_vec(&b).unwrap(),
                }
            }
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
        let introspect = Introspect::new(http_client, introspect_ep, None);
        IssuerService::new(
            metadata,
            inner,
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
                        "family_name": {},
                        "dob": {}
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