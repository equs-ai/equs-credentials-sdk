use async_trait::async_trait;
use url::Url;

use crate::core_::{vault, vc};
use crate::exchange::oid4vc::oid4vci;
use crate::exchange::oid4vc::oid4vp;
use crate::exchange::oid4vc::oid4vp::{
    AuthorizationRequest, AuthorizationResponse, PresentationDefinition
};
use crate::exchange::oid4vc::oid4vp::holder::{CredentialsMap, ResolvedAuthRequest};
use crate::facade::facade_low_level;

//  --------- DATA MODEL -------------

pub type IssuerMetadata = oid4vci::IssuerMetadata;
pub type AuthorizationMetadata = oid4vci::AuthorizationMetadata;
pub struct WalletMetadata {}

pub type CredentialClaims = facade_low_level::CredentialClaims;
pub type CredentialClaimsRaw = serde_json::Value;
pub type CredentialResult = oid4vci::CredentialResult;

pub type Credential = vc::Credential;
pub type CredentialMetadata = facade_low_level::CredentialMetadata;

pub type TokenResponse = oid4vci::TokenResponse;
pub type CredentialRequest = oid4vci::CredentialRequest;
pub type CredentialResponse = oid4vci::CredentialResponse;
pub type CredentialOfferGrants = oid4vci::CredentialOfferGrants;
pub type CredentialOfferParameters = oid4vci::CredentialOfferParameters;

pub struct AuthorizationResponseMetadata {}
pub type CredentialMapping = CredentialsMap;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    // service
    #[error(transparent)]
    Issuer(#[from] oid4vci::issuer::Error),
    #[error(transparent)]
    HolderVci(#[from] oid4vci::holder::Error),

    #[error(transparent)]
    Verifier(#[from] oid4vp::error::Error),

    #[error(transparent)]
    HolderVP(#[from] oid4vp::holder::Error),

    // internal apis
    #[error(transparent)]
    Facade(#[from] facade_low_level::Error),
    #[error(transparent)]
    Vault(#[from] vault::Error),

    // common
    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),
}

pub type Result<T> = core::result::Result<T, Error>;

// NOTE: THE API is Subject to Change

// API

// Out-of-scope: Authorization Server (Key Cloak) for OAuth 2 (Authorization code flow):
// GET /authorize
// POST /token 

#[async_trait]
pub trait Issuer {
    // Step 1: Init Issuer Service
    // via constructors

    // Step 2
    // GET /<credential_offer_uri> or pass by value
    fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants, // grant type (auth code, pre-auth code), etc.
    ) -> Result<(CredentialOfferParameters, Url)>;


    // Step 3.2
    // GET /.well-known/openid-credential-issuer HTTP/1.1
    fn get_issuer_metadata(&self) -> IssuerMetadata;


    // Step 6.2
    // POST /credential HTTP/1.1
    async fn issue_credential(
        &mut self,
        cred_request: &CredentialRequest,
        token: &String,
        claims: &CredentialClaims,
    ) -> Result<CredentialResponse>;
}

#[async_trait]
pub trait HolderVci {
    // Step 3.1 Init Holder
    // via constructors
    // Calls GET /.well-known/openid-credential-issuer HTTP/1.1

    // Step 4: Return Issuer Metadata to display Credential Schema on UI
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    // Step 5: Get AuthToken using Authorization Code Flow with Scope
    async fn authz_code_flow_with_scope(
        &self,
        cred_def_id: String,
        authorization_callback: impl FnOnce(Url) -> String + Send,
    ) -> Result<TokenResponse>;

    // Step 5: Get AuthToken using Pre-authoriozed code flow
    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> Result<TokenResponse>;

    // Step 6.1: Get Credential by the AuthToken
    async fn request_credential(
        &self,
        token_response: &TokenResponse,
        cred_def_id: &str,
    ) -> Result<CredentialResult>;

    // Step 7
    async fn store_credential(
        &mut self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<()>;
}

#[async_trait]
pub trait HolderVp {
    // Step 8.2
    // (Optional) AuthRequest can be sent out-of-band or by GET to auth-req-uri (this call)
    async fn get_authorization_request(
        &self,
        auth_req_uri: &str,
    ) -> Result<ResolvedAuthRequest>;

    // Step 9
    // Assume credentials for presentations are selected automatically
    // If there is just one credential matching a presentation request - it's selected
    // If there are multiple selection matching - they are selected according to a default logic (such as take the first one)
    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>>;

    // Step 9.1
    // Manual approval/consent of credentials to be used for presentation
    // Step 7A1 - find matching credentials
    async fn find_vcs_for_presentation(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<CredentialMapping>;

    // Step 9.2
    // Manual approval/consent of credentials to be used for presentation
    // Step 5A2 - create presentation for a unambiguous Mapping where there is a VC for every presentation request item
    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        credential_mapping_selected: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>>;
}


pub trait Verifier {
    // Step 8.1
    // GET /<authorization_req_uri> or pass by value
    async fn create_authorization_request(
        &mut self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        response_uri: Url,
    ) -> Result<AuthorizationRequest>;

    // Step 10
    // POST <authorization-response-uri>
    async fn verify_presentation(
        &mut self,
        authorization_response: &AuthorizationResponse,
    ) -> Result<CredentialClaimsRaw>;
}
