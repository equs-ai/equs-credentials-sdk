use serde::{Deserialize, Serialize};
use crate::crypto::Alg;

pub use crate::vc::formats::vc::*;
pub use crate::vc::formats::vp::*;

mod formats;
mod pop;

pub mod core;
pub mod oid4vci;
pub mod oid4vp;
pub mod metadata;

/// Verifiable Credential (`VC`)
///
/// Each enum value represents different format of `VC` and contains an actual serializable `VC` body.
///
/// *NOTE*: could be extended in the next releases.
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

impl HasVCFormat for Credential {
    fn format(&self) -> VCFormat {
        match self {
            Credential::JwtVcJson(_) => VCFormat::JwtVcJson,
            Credential::JwtVcJsonLd(_) => VCFormat::JwtVcJsonLD,
            Credential::LdpVc(_) => VCFormat::LdpVc,
            Credential::SdJwt(_) => VCFormat::SdJwtVc,
        }
    }
}

/// Credential Metadata.
///
/// Contains the various data related to some `Credential`.
///
/// Currently, only `type` and `format` are mandatory.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    #[serde(rename = "type")]
    pub type_: String,
    pub format: VCFormat,
    pub alg: Option<Alg>,
    pub tags: Vec<(String, String)>,
}

/// Verifiable Presentation (`VP`)
///
/// Each enum value represents different format of `VP` and contains an actual serializable `VP` body.
///
/// *NOTE*: could be extended in the next releases.
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

/// Basic format for `Claims`.
pub type Claims = serde_json::Value;