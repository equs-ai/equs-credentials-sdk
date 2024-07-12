use oauth2::url::Url;
use oid4vci::core::profiles;
use oid4vci::openidconnect::Nonce;
use crate::core_::{kms, vc};
use crate::core_::kms::KeyID;

// Error handling
pub enum OidError {}

// Basic types definitions

pub type CredentialOffer = profiles::CoreProfilesOffer;
pub type CredentialRequest = profiles::CoreProfilesRequest;
pub type IssuerMetadata = oid4vci::core::metadata::IssuerMetadata;
pub type ProofOfPossession = oid4vci::proof_of_possession::ProofOfPossession;

pub type PresentationDefinition = oidc4vp::presentation_exchange::PresentationDefinition;

pub type AuthorizationCode = oauth2::AuthorizationCode;
pub type AccessToken = oauth2::AccessToken;

// Data structures

// Methods results

pub enum CredentialResult {
    Deferred { transaction_id: String },
    Credential { credential: vc::Credential, notification_id: String },
}

pub trait Issuer
{
    async fn metadata() -> IssuerMetadata;

    // including validation for scope
    async fn validate_token(token: AccessToken) -> Result<(), OidError>;

    async fn validate_request(req: CredentialRequest) -> Result<(), OidError>;

    async fn verify_proof(pop: ProofOfPossession, nonce: Option<Nonce>) -> Result<(), OidError>;

    // infers credential format from CredRequest
    async fn issue_credential(req: CredentialRequest, material: impl vc::ToCredential, key_id: KeyID) -> Result<vc::Credential, OidError>;

    // deferred credential and transaction mgmt, extra steps for validation/3p integration is out-of-scope and should be done on Application layer
}

pub trait HolderAuthz {
    async fn from_metadata(issuer_url: Url) -> Result<impl HolderAuthz, OidError>;

    async fn from_offer(offer: Url) -> Result<impl HolderAuthz, OidError>;

    async fn pushed_authz(pkce_challenge: String) -> Result<AuthorizationCode, OidError>;

    async fn exchange_code(authz_code: String, pkce_verifier: String) -> Result<AccessToken, OidError>;
}

pub trait Holder: HolderAuthz
{
    async fn request(token: AccessToken, req: CredentialRequest, proof_key: Option<impl kms::KeyHandle>) -> Result<CredentialResult, OidError>;

    async fn deferred(token: AccessToken, transaction_id: String) -> Result<CredentialResult, OidError>;
}