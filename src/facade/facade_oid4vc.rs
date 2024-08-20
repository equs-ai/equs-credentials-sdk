use async_trait::async_trait;
use url::Url;

use crate::core_::vault;
use crate::exchange::oid4vc::oid4vp;
use crate::exchange::oid4vc::oid4vp::{
    AuthorizationRequest, AuthorizationResponse, PresentationDefinition,
};
use crate::exchange::oid4vc::oid4vp::holder::{CredentialsMap, ResolvedAuthRequest};
use crate::facade::facade_low_level;

//  --------- DATA MODEL -------------

pub type CredentialClaimsRaw = serde_json::Value;
pub struct AuthorizationResponseMetadata {}
pub type CredentialMapping = CredentialsMap;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
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

#[async_trait]
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
