use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::crypto;

mod formats;
mod pop;
pub mod core;
pub mod oid4vci;
pub mod oid4vp;

pub const JWT_VC_JSON: &str = "jwt_vc_json";
pub const JWT_VC_JSON_LD: &str = "jwt_vc_json-ld";
pub const LDP_VC: &str = "ldp_vc";
pub const SD_JWT_VC: &str = "vc+sd-jwt";
pub const JWT_VP: &str = "jwt_vp";
pub const LDP_VP: &str = "ldp_vp";

// VC formats

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
}

impl Into<&'static str> for &VCFormat {
    fn into(self) -> &'static str {
        match self {
            VCFormat::JwtVcJson => "jwt_vc_json",
            VCFormat::JwtVcJsonLD => "jwt_vc_json-ld",
            VCFormat::LdpVc => "ldp_vc",
            VCFormat::SdJwtVc => "vc+sd-jwt",
        }
    }
}

impl Display for VCFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str: &str = self.into();
        write!(f, "{}", str)
    }
}

// VP format

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum VPFormat {
    JwtVp,
    LdpVp,
}

impl Into<&'static str> for VPFormat {
    fn into(self) -> &'static str {
        match self {
            VPFormat::JwtVp => "jwt_vp",
            VPFormat::LdpVp => "ldp_vp",
        }
    }
}

// Credential

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Credential {
    // W3C
    JwtVcJson(String),
    JwtVcJsonLd(String),
    LdpVc(ssi::vc::Credential),
    // SD-JWT
    SdJwt(String),
    // etc
    // ISOMdl(String),
}

impl Credential {
    pub fn format(&self) -> VCFormat {
        match self {
            Credential::JwtVcJson(_) => VCFormat::JwtVcJson,
            Credential::JwtVcJsonLd(_) => VCFormat::JwtVcJsonLD,
            Credential::LdpVc(_) => VCFormat::LdpVc,
            Credential::SdJwt(_) => VCFormat::SdJwtVc,
        }
    }
}

// TODO: prune metadata
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub id: String,
    pub format: VCFormat,
    pub alg: crypto::Alg,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(untagged)]
pub enum Presentation {
    // W3C
    JwtVp(ssi::vc::Presentation),
    LdpVp(ssi::vc::Presentation),
    // SD-JWT
    SdJwtVp(String),
}

pub type Claims = serde_json::Value;