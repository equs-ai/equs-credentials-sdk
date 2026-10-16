use equs_sdk::vc::oid4vp::{ResponseMode, ResponseType};
use serde::{Deserialize, Serialize};
use strum_macros::Display;

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthRequestQuery {
    #[serde(default = "default_response_type")]
    pub response_type: ResponseType,
    #[serde(default = "default_response_mode")]
    pub response_mode: ResponseMode,
    #[serde(default)]
    pub query_type: PresentationQueryType,
}

impl Default for AuthRequestQuery {
    fn default() -> Self {
        Self {
            response_type: ResponseType::VpToken,
            response_mode: ResponseMode::DirectPostJwt,
            query_type: PresentationQueryType::DCQL,
        }
    }
}

fn default_response_type() -> ResponseType {
    ResponseType::VpToken
}

fn default_response_mode() -> ResponseMode {
    ResponseMode::DirectPostJwt
}

#[derive(Debug, Default, Deserialize, Display, Serialize)]
pub enum PresentationQueryType {
    DCQL,
    #[default]
    PresentationDefinition,
}
