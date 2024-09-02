use std::fmt::{Display, Formatter};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::vc::{formats};
use crate::vc::formats::{FormatNotSupportedSnafu, Error};

pub const JWT_VC_JSON: &str = "jwt_vc_json";
pub const JWT_VC_JSON_LD: &str = "jwt_vc_json-ld";
pub const LDP_VC: &str = "ldp_vc";
pub const SD_JWT_VC: &str = "vc+sd-jwt";

/// Basic enum for supported `VC` formats.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
}

pub trait HasVCFormat {
    fn format(&self) -> VCFormat;
}

impl Into<&'static str> for &VCFormat {
    fn into(self) -> &'static str {
        match self {
            VCFormat::JwtVcJson => JWT_VC_JSON,
            VCFormat::JwtVcJsonLD => JWT_VC_JSON_LD,
            VCFormat::LdpVc => LDP_VC,
            VCFormat::SdJwtVc => SD_JWT_VC,
        }
    }
}

impl FromStr for VCFormat {
    type Err = Error;

    fn from_str(s: &str) -> formats::Result<VCFormat> {
        match s {
            JWT_VC_JSON => Ok(VCFormat::JwtVcJson),
            JWT_VC_JSON_LD => Ok(VCFormat::JwtVcJsonLD),
            LDP_VC => Ok(VCFormat::LdpVc),
            SD_JWT_VC => Ok(VCFormat::SdJwtVc),
            _ => FormatNotSupportedSnafu { format: s }.fail(),
        }
    }
}

impl Display for VCFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str: &str = self.into();
        write!(f, "{}", str)
    }
}