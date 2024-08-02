use async_trait::async_trait;
use oid4vci::credential_offer::CredentialOfferGrants;
use url::Url;

use crate::core_::vc;
use crate::exchange::oid4vc::{vci, vci_issuer};
use crate::exchange::oid4vc::vci::CredentialOfferParameters;
use crate::facade::facade_low_level;

//  --------- DATA MODEL -------------

pub type IssuerMetadata = vci::IssuerMetadata;
pub type AuthorizationMetadata = vci::AuthorizationMetadata;
pub struct WalletMetadata {}

pub type CredentialClaims = facade_low_level::CredentialClaims;
pub type CredentialClaimsRaw = serde_json::Value;
pub type CredentialResult = vci::CredentialResult;

pub type Credential = vc::Credential;
pub type CredentialMetadata = facade_low_level::CredentialMetadata;

pub type TokenResponse = vci::TokenResponse;
pub type CredentialRequest  = vci::CredentialRequest;
pub type CredentialResponse = vci::CredentialResponse;

pub struct AuthorizationRequest {
    client_id: String,
    request_object_jwt: String,
    authorization_endpoint: Url,
}

pub struct AuthorizationResponse {
    vp_token: serde_json::Value,
    presentation_submission: PresentationSubmission,
}

pub struct AuthorizationResponseMetadata {}

pub struct PresentationDefinition {}
pub struct PresentationSubmission {}
pub struct CredentialMapping {}


#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Issuer(#[from] vci_issuer::Error),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),
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
        authorization_callback: impl FnOnce(Url) -> String,
    ) -> Result<TokenResponse>;

    // Step 5: Get AuthToken using Pre-authoriozed code flow
    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
    ) -> Result<TokenResponse>;

    // Step 6.1: Get Credential by the AuthToken
    async fn request_credential(
        &self,
        token_response: &TokenResponse,
        credential_request: &CredentialRequest,
    ) -> Result<CredentialResult>;

    // Step 7
    async fn store_credential(
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<()>;
}

#[async_trait]
pub trait HolderVp {
    // Step 8.2
    // (Optional) AuthRequest can be sent out-of-band or by GET to auth-req-uri (this call)
    fn get_authorization_request(
        auth_req_uri: &str,
    ) -> Result<AuthorizationRequest>;

    // Step 9
    // Assume credentials for presentations are selected automatically
    // If there is just one credential matching a presentation request - it's selected
    // If there are multiple selection matching - they are selected according to a default logic (such as take the first one)
    fn present_credentials_auto(
        auth_request: &AuthorizationRequest,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<()>;

    // Step 9.1
    // Manual approval/consent of credentials to be used for presentation
    // Step 7A1 - find matching credentials
    fn find_vcs_for_presentation(
        auth_request: &AuthorizationRequest,
    ) -> Result<CredentialMapping>;

    // Step 9.2
    // Manual approval/consent of credentials to be used for presentation
    // Step 5A2 - create presentation for a unambiguous Mapping where there is a VC for every presentation request item
    fn present_credentials(
        auth_request: &AuthorizationRequest,
        credential_mapping_selected: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<()>;
}


pub trait Verifier {
    // Step 8.1
    // GET /<authorization_req_uri> or pass by value
    async fn create_authorization_request(
        &mut self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        wallet_metadata: WalletMetadata,
        response_uri: Url,
    ) -> Result<AuthorizationRequest>;

    // Step 10
    // POST <authorization-response-uri>
    async fn verify_presentation(
        &mut self,
        authorization_response: &AuthorizationResponse,
    ) -> Result<CredentialClaimsRaw>;
}
