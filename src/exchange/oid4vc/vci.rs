use oauth2::url::Url;
use oid4vci::core::profiles::{CoreProfilesOffer, CoreProfilesResponse, sd_jwt, w3c};
use oid4vci::openidconnect::Nonce;

use crate::core_::{did, vc};
use crate::core_::did::DIDURL;
use crate::core_::kms::KeyID;
use crate::core_::vc::Credential;
use crate::exchange::oid4vc::{AccessToken, Error};
use crate::facade::facade_low_level::CredentialMetadata;

pub type IssuerMetadata = oid4vci::core::metadata::IssuerMetadata;
pub type CredentialRequest = oid4vci::core::credential::Request;
pub type CredentialResponse = oid4vci::core::credential::Response;
pub type ProofOfPossession = oid4vci::proof_of_possession::ProofOfPossession;
pub type Proof = oid4vci::proof_of_possession::Proof;

pub type CredentialOffer = oid4vci::credential_offer::CredentialOffer<CoreProfilesOffer>;
pub type CredentialOfferParams = oid4vci::credential_offer::CredentialOfferParameters<CoreProfilesOffer>;
pub type CredentialOfferParameters = oid4vci::credential_offer::CredentialOfferParameters<CoreProfilesOffer>;
pub type CredentialProfileMetadata = oid4vci::core::profiles::CoreProfilesMetadata;
pub type AuthorizationResponse = oid4vci::token::Response;

pub enum CredentialResult {
    Deferred { transaction_id: String },
    Credential { credential: vc::Credential, notification_id: Option<String> },
}

pub struct IssuanceMetadata {
    pub core_metadata: CredentialMetadata,
    pub nonce: Option<Nonce>,
    pub notification_id: Option<String>,
}

impl From<&Proof> for crate::facade::facade_low_level::ProofOfPossession {
    fn from(value: &Proof) -> crate::facade::facade_low_level::ProofOfPossession {
        match value {
            Proof::JWT { jwt } => { crate::facade::facade_low_level::ProofOfPossession { format: "jwt".to_string(), proof: jwt.to_string() } }
            Proof::CWT { cwt } => { crate::facade::facade_low_level::ProofOfPossession { format: "cwt".to_string(), proof: cwt.to_owned() } }
        }
    }
}

impl Into<CoreProfilesResponse> for Credential {
    fn into(self) -> CoreProfilesResponse {
        match self {
            Credential::JwtVcJson(cred) => { CoreProfilesResponse::JWTVC(w3c::jwt::Response::new(cred)) }
            Credential::JwtVcJsonLd(_) => { CoreProfilesResponse::JWTLDVC(w3c::jwtld::Response {}) }
            Credential::LdpVc(cred) => { CoreProfilesResponse::LDVC(w3c::ldp::Response::new(cred)) }
            Credential::SdJwt(cred) => { CoreProfilesResponse::SDJWTVC(sd_jwt::Response::new(cred)) }
        }
    }
}

pub fn credential_profile_metadata_format(profile: &CredentialProfileMetadata) -> String {
    match profile {
        oid4vci::core::profiles::CoreProfilesMetadata::SDJWTVC(_) => { "vc+sd-jwt".to_string() }
        oid4vci::core::profiles::CoreProfilesMetadata::JWTVC(_) => { "jwt_vc_json".to_string() }
        oid4vci::core::profiles::CoreProfilesMetadata::JWTLDVC(_) => { "jwt_vc_json-ld".to_string() }
        oid4vci::core::profiles::CoreProfilesMetadata::LDVC(_) => { " ldp_vc".to_string() }
        oid4vci::core::profiles::CoreProfilesMetadata::ISOmDL(_) => { "mso_mdoc".to_string() }
    }
}

pub trait Issuer
{
    async fn metadata(&self) -> IssuerMetadata;

    async fn offer_pre_authz_flow(&self, code: &str, cred_ids: &Vec<String>) -> Result<CredentialOfferParams, Error>;

    async fn offer_authz_flow(&self, iss_state: Option<String>, cred_ids: &Vec<String>) -> Result<CredentialOfferParams, Error>;

    // including validation for scope
    async fn validate_token(&self, token: AccessToken) -> Result<(), Error>;

    async fn validate_request(&self, req: CredentialRequest) -> Result<(), Error>;

    async fn verify_proof(&self, pop: Proof, nonce: Nonce) -> Result<(), Error>;

    // infers credential format from CredRequest
    async fn issue_credential<CM>(&self, req: CredentialRequest, claims: CM, did_url: did::DIDURL, key_id: KeyID) -> Result<vc::Credential, Error>;
}


pub trait Holder: Sized {
    async fn from_metadata(issuer_url: Url) -> Result<Self, Error>;

    async fn from_offer(offer: CredentialOffer) -> Result<Self, Error>;

    fn supported_cred_ids() -> Vec<String>;

    // Runs all Authorization Code flow logic to retrieve Access Token and nonce for requesting credential
    async fn authz_code_flow(&self, cred_ids: &Vec<String>, callback: fn(Url) -> String) -> Result<AuthorizationResponse, Error>;

    // Runs all Pre-authorized Code flow logic to retrieve Access Token and nonce for requesting credential
    async fn pre_authorized_flow(&self, cred_ids: &Vec<String>) -> Result<AuthorizationResponse, Error>;

    // Issuing
    async fn request(&self, token: AccessToken, req: CredentialRequest,
                     nonce: Option<vc::Nonce>, proof_did_url: Option<DIDURL>, proof_kid: Option<KeyID>,
    ) -> Result<CredentialResult, Error>;

    async fn deferred(&self, token: AccessToken, transaction_id: String) -> Result<CredentialResult, Error>;
}