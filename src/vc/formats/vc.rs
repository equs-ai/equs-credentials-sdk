use crate::vc::formats;
use crate::vc::formats::{Error, FormatNotSupportedSnafu};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub const JWT_VC_JSON: &str = "jwt_vc_json";
pub const JWT_VC_JSON_LD: &str = "jwt_vc_json-ld";
pub const LDP_VC: &str = "ldp_vc";
pub const SD_JWT_VC: &str = "dc+sd-jwt";
pub const MSO_MDOC: &str = "mso_mdoc";

/// Basic enum for supported `VC` formats.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
    MsoMdoc,
}

pub trait HasVCFormat {
    fn format(&self) -> VCFormat;
}

impl From<&VCFormat> for &'static str {
    fn from(value: &VCFormat) -> Self {
        match value {
            VCFormat::JwtVcJson => JWT_VC_JSON,
            VCFormat::JwtVcJsonLD => JWT_VC_JSON_LD,
            VCFormat::LdpVc => LDP_VC,
            VCFormat::SdJwtVc => SD_JWT_VC,
            VCFormat::MsoMdoc => MSO_MDOC,
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
            MSO_MDOC => Ok(VCFormat::MsoMdoc),
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case::jwt_vc_json(JWT_VC_JSON, VCFormat::JwtVcJson)]
    #[case::jwt_vc_json_ld(JWT_VC_JSON_LD, VCFormat::JwtVcJsonLD)]
    #[case::ldp_vc(LDP_VC, VCFormat::LdpVc)]
    #[case::sd_jwt_vc(SD_JWT_VC, VCFormat::SdJwtVc)]
    #[case::mso_mdoc(MSO_MDOC, VCFormat::MsoMdoc)]
    fn vc_format_from_str_parses_known_strings(#[case] s: &str, #[case] expected: VCFormat) {
        assert_eq!(VCFormat::from_str(s).unwrap(), expected);
    }

    #[test]
    #[should_panic(expected = "Unsupported format: unknown")]
    fn vc_format_from_str_rejects_unknown() {
        VCFormat::from_str("unknown").unwrap();
    }

    #[rstest]
    #[case::jwt_vc_json(VCFormat::JwtVcJson, JWT_VC_JSON)]
    #[case::jwt_vc_json_ld(VCFormat::JwtVcJsonLD, JWT_VC_JSON_LD)]
    #[case::ldp_vc(VCFormat::LdpVc, LDP_VC)]
    #[case::sd_jwt_vc(VCFormat::SdJwtVc, SD_JWT_VC)]
    #[case::mso_mdoc(VCFormat::MsoMdoc, MSO_MDOC)]
    fn vc_format_display_matches_string_constant(#[case] fmt: VCFormat, #[case] expected: &str) {
        assert_eq!(fmt.to_string(), expected);
    }

    #[rstest]
    #[case::jwt_vc_json(VCFormat::JwtVcJson, JWT_VC_JSON)]
    #[case::jwt_vc_json_ld(VCFormat::JwtVcJsonLD, JWT_VC_JSON_LD)]
    #[case::ldp_vc(VCFormat::LdpVc, LDP_VC)]
    #[case::sd_jwt_vc(VCFormat::SdJwtVc, SD_JWT_VC)]
    #[case::mso_mdoc(VCFormat::MsoMdoc, MSO_MDOC)]
    fn vc_format_from_ref_yields_static_str_constant(
        #[case] fmt: VCFormat,
        #[case] expected: &'static str,
    ) {
        let s: &'static str = (&fmt).into();
        assert_eq!(s, expected);
    }
}
