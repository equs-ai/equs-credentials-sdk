pub mod core;
pub mod oid4vci;
pub mod oid4vp;
pub mod status_formats;

pub type JsonObject = serde_json::Map<String, serde_json::Value>;
