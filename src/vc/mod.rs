use crate::crypto::Alg;
use crate::vc::formats::{sd_jwt_vc, FormatNotSupportedSnafu, HasCredential};
use serde::{Deserialize, Serialize};

pub use crate::vc::formats::json_ld_vc::{
    JsonLdAPI as VCFormatsJsonLdAPI, VCMetadata as JsonLdAPIVCMetadata,
};
pub use crate::vc::formats::sd_jwt_vc::{SdJwtAPI as VCFormatsSdJwtAPI, VCMetadata};
pub use crate::vc::formats::vc::*;
pub use crate::vc::formats::vp::*;
pub use crate::vc::formats::Error as VCFormatError;
pub use crate::vc::formats::API as VCFormatsAPI;
pub use crate::vc::presentation_exchange::ClaimFormat;

mod formats;
mod pop;
pub mod presentation_exchange;

pub mod core;
pub mod metadata;
pub mod oid4vci;
pub mod oid4vp;

pub use formats::HasClaims;

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
    SdJwt(sd_jwt_vc::Credential),
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
    pub kid: String,
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

impl HasVPFormat for Presentation {
    fn format(&self) -> VPFormat {
        match self {
            Presentation::JwtVp(_) => VPFormat::JwtVp,
            Presentation::LdpVp(_) => VPFormat::LdpVp,
            Presentation::SdJwtVp(_) => VPFormat::SdJwtVp,
        }
    }
}

impl HasCredential<Credential> for Presentation {
    fn get_credential(&self) -> formats::Result<Credential> {
        match &self {
            Presentation::SdJwtVp(presentation) => {
                Ok(Credential::SdJwt(presentation.get_credential()?))
            }
            Presentation::LdpVp(presentation) => {
                Ok(Credential::LdpVc(presentation.get_credential()?))
            }
            _ => FormatNotSupportedSnafu {
                format: self.format().to_string(),
            }
            .fail(),
        }
    }
}

/// Basic format for `Claims`.
pub type Claims = serde_json::Value;
