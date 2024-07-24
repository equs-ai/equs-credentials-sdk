use serde_json::Map;

use crate::core_::vc;

pub const SD_JWT_VC: &str = "vc+sd-jwt";

// Basic types definitions
pub type Claims = Map<String, serde_json::Value>;
pub type Credential = vc::JWTRaw;
pub type Presentation = vc::JWTRaw;
pub type Disclosure = &'static str;