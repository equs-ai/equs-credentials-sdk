use crate::core_::vc;

pub const JWT_VC_JSON: &str = "jwt_vc_json";
pub const JWT_VC_JSON_LD: &str = "jwt_vc_json-ld";
pub const JWT_VP: &str = "jwt_vp";

pub type Claims = ssi::vc::Credential;
pub type Credential = vc::JWTRaw;
pub type Presentation = ssi::vc::Presentation;