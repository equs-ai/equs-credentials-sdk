use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

pub const SD_JWT_VP: &str = "vc+sd-jwt";
pub const JWT_VP: &str = "jwt_vp";
pub const LDP_VP: &str = "ldp_vp";

/// Basic enum for supported `VP` formats.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VPFormat {
    SdJwtVp,
    JwtVp,
    LdpVp,
}

pub trait HasVPFormat {
    fn format(&self) -> VPFormat;
}

impl From<&VPFormat> for &'static str {
    fn from(value: &VPFormat) -> Self {
        match value {
            VPFormat::SdJwtVp => SD_JWT_VP,
            VPFormat::JwtVp => JWT_VP,
            VPFormat::LdpVp => LDP_VP,
        }
    }
}

impl Display for VPFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str: &str = self.into();
        write!(f, "{}", str)
    }
}
