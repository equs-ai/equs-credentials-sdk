use serde_json::Map;

use crate::core_::vc;

// Basic types definitions
pub type Claims = Map<String, serde_json::Value>;
pub type Credential = vc::JWTRaw;
pub type Presentation = vc::JWTRaw;
pub type Disclosure = &'static str;