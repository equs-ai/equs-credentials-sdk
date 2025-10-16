//! SSI standards implementations.

use crate::crypto::Alg;
use crate::vc::claims::Claims;
pub use crate::vc::formats::API as VCFormatsAPI;
pub use crate::vc::formats::Error as VCFormatError;
pub use crate::vc::formats::json_ld_vc::{
    JsonLdAPI as VCFormatsJsonLdAPI, VCMetadata as JsonLdAPIVCMetadata,
};
pub use crate::vc::formats::sd_jwt_vc::{SdJwtAPI as VCFormatsSdJwtAPI, VCMetadata};
pub use crate::vc::formats::vc::*;
pub use crate::vc::formats::vp::*;
use crate::vc::formats::{FormatNotSupportedSnafu, HasCredential, IsExpired, IsValid, sd_jwt_vc};
pub use crate::vc::presentation_exchange::ClaimFormat;
use crate::vc::status_formats::status_list_token_jwt;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashMap;

pub(crate) mod formats;
mod pop;
pub mod presentation_exchange;
pub mod status_formats; // TODO: check visibility

pub mod claims;
pub mod core;
pub mod dcql;
pub mod metadata;
pub mod oid4vci;
pub mod oid4vp;

use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
pub use formats::HasClaims;

/// `Credential` Error.
///
/// All implementations of [Credential] should leverage this enum for error handling.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum CredentialError {
    #[snafu(display("Error during parsing claims"))]
    ParseClaims {
        source: formats::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Could not check expiration status"))]
    ExpirationCheck {
        source: formats::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Status validation error: {source}"))]
    StatusValidation {
        source: formats::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

type Result<T> = std::result::Result<T, CredentialError>;

pub type ClaimFormatDesignation = openid4vp::core::credential_format::ClaimFormatDesignation;
pub type JsonPath = serde_json_path::JsonPath;
#[derive(Debug, Clone)]
pub(crate) struct RequestedPresentation {
    pub id: String,
    pub presentation: Presentation,
    pub require_cryptographic_holder_binding: Option<bool>,
}

/// Verifiable Credential (`VC`)
///
/// Each enum value represents different format of `VC` and contains an actual serializable `VC` body.
///
/// *NOTE*: could be extended in the next releases.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Credential {
    // SD-JWT
    SdJwt(sd_jwt_vc::Credential),
    // W3C
    LdpVc(formats::json_ld_vc::VC),
    JwtVcJson(String),
    JwtVcJsonLd(String),
    // etc
    // ISOMdl(String),
}

impl Credential {
    pub fn is_expired(&self) -> Result<bool> {
        Ok(match self {
            Credential::SdJwt(credential) => {
                let claims = credential.parse_claims().context(ParseClaimsSnafu)?;
                SdJwtAPI::is_expired(&claims).context(ExpirationCheckSnafu)?
            }
            Credential::LdpVc(credential) => {
                JsonLdAPI::is_expired(credential).context(ExpirationCheckSnafu)?
            }
            _ => false,
        })
    }

    pub async fn is_valid(
        &self,
        http_client: &dyn HttpClient,
        did_resolver: UniversalResolver,
        cached_status_list_jwts: Option<&mut HashMap<String, String>>,
    ) -> Result<bool> {
        match self {
            Credential::SdJwt(credential) => {
                let claims = credential.parse_claims().context(ParseClaimsSnafu)?;
                SdJwtAPI::is_valid(&claims, http_client, did_resolver, cached_status_list_jwts)
                    .await
                    .context(StatusValidationSnafu)
            }
            _ => Ok(true),
        }
    }
}

/// Enum to represent the different ways to encode VC Statuses data.
#[derive(Debug)]
#[non_exhaustive]
pub enum VCStatusesData {
    StatusListToken(status_list_token_jwt::VCStatuses),
    BitstringStatusList, // Not supported yet
}

/// Enum to provide an abstraction over the underlying VC status representation.
#[derive(Debug)]
pub enum VCStatus {
    StatusListToken(status_list_token_jwt::VCStatus),
    // BitstringStatusList,
}

/// Enum to represent different types of status lists.
#[derive(Debug)]
pub enum StatusList {
    StatusListTokenJwt(status_list_token_jwt::StatusList),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Alg>,
    pub fields: Vec<String>,
}

/// Verifiable Presentation (`VP`)
///
/// Each enum value represents different format of `VP` and contains an actual serializable `VP` body.
///
/// *NOTE*: could be extended in the next releases.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(untagged)]
pub enum Presentation {
    // W3C
    JwtVp(String),
    LdpVp(formats::json_ld_vc::VP),
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

impl HasClaims<Claims> for Credential {
    fn parse_claims(&self) -> formats::Result<Claims> {
        match &self {
            Credential::SdJwt(vc) => vc.parse_claims(),
            Credential::LdpVc(vc) => vc.parse_claims(),
            _ => FormatNotSupportedSnafu {
                format: self.format().to_string(),
            }
            .fail(),
        }
    }
}
