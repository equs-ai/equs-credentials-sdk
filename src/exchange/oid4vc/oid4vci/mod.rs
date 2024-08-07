use oid4vci::core::profiles::{CoreProfilesOffer, CoreProfilesResponse, sd_jwt, w3c};
use oid4vci::core::profiles::CoreProfilesMetadata;
use oid4vci::openidconnect::Nonce;
use serde::{Deserialize, Serialize};

use crate::core_::vc;
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::CredentialMetadata;

pub mod issuer;
pub mod holder;


pub type IssuerMetadata = oid4vci::core::metadata::IssuerMetadata;
pub type AuthorizationMetadata = oid4vci::metadata::AuthorizationMetadata;

pub type TokenResponse = oid4vci::token::Response;

pub type CredentialRequest = oid4vci::core::credential::Request;
pub type CredentialResponse = oid4vci::core::credential::Response;
pub type Proof = oid4vci::proof_of_possession::Proof;

pub type CredentialOffer = oid4vci::core::credential_offer::CredentialOffer;
pub type CredentialOfferGrants = oid4vci::credential_offer::CredentialOfferGrants;
pub type CredentialOfferParameters = oid4vci::credential_offer::CredentialOfferParameters<CoreProfilesOffer>;
pub type CredentialProfileMetadata = CoreProfilesMetadata;
pub type AuthorizationResponse = oid4vci::token::Response;

#[derive(Debug, Clone)]
pub enum CredentialResult {
    Deferred { transaction_id: String },
    Credential { credential: vc::Credential, notification_id: Option<String> },
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct IssuanceMetadata {
    pub core_metadata: CredentialMetadata,
    pub nonce: Option<Nonce>,
    pub notification_id: Option<String>,
}

impl From<&Proof> for facade_low_level::ProofOfPossession {
    fn from(value: &Proof) -> facade_low_level::ProofOfPossession {
        match value {
            Proof::JWT { jwt } => { facade_low_level::ProofOfPossession { format: "jwt".to_string(), proof: jwt.to_string() } }
            Proof::CWT { cwt } => { facade_low_level::ProofOfPossession { format: "cwt".to_string(), proof: cwt.to_owned() } }
        }
    }
}

impl Into<CoreProfilesResponse> for vc::Credential {
    fn into(self) -> CoreProfilesResponse {
        match self {
            vc::Credential::JwtVcJson(cred) => { CoreProfilesResponse::JWTVC(w3c::jwt::Response::new(cred)) }
            vc::Credential::JwtVcJsonLd(_) => { CoreProfilesResponse::JWTLDVC(w3c::jwtld::Response {}) }
            vc::Credential::LdpVc(cred) => { CoreProfilesResponse::LDVC(w3c::ldp::Response::new(cred)) }
            vc::Credential::SdJwt(cred) => { CoreProfilesResponse::SDJWTVC(sd_jwt::Response::new(cred)) }
        }
    }
}

pub fn credential_profile_metadata_format(profile: &CoreProfilesMetadata) -> String {
    match profile {
        CoreProfilesMetadata::SDJWTVC(_) => { "vc+sd-jwt".to_string() }
        CoreProfilesMetadata::JWTVC(_) => { "jwt_vc_json".to_string() }
        CoreProfilesMetadata::JWTLDVC(_) => { "jwt_vc_json-ld".to_string() }
        CoreProfilesMetadata::LDVC(_) => { " ldp_vc".to_string() }
        CoreProfilesMetadata::ISOmDL(_) => { "mso_mdoc".to_string() }
    }
}