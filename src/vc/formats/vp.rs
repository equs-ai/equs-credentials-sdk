pub const JWT_VP: &str = "jwt_vp";
pub const LDP_VP: &str = "ldp_vp";

/// Basic enum for supported `VP` formats.
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum VPFormat {
    JwtVp,
    LdpVp,
}

impl From<VPFormat> for &'static str {
    fn from(value: VPFormat) -> Self {
        match value {
            VPFormat::JwtVp => JWT_VP,
            VPFormat::LdpVp => LDP_VP,
        }
    }
}
