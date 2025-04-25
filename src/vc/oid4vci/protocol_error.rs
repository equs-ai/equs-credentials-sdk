use crate::vc::oid4vci::ErrorType;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::fmt::Debug;

/// A protocol-specific `oid4vci` error response.
///
/// Those errors are defined in the standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// Should be treated like 4xx errors.
#[derive(Snafu, Clone, Deserialize, Serialize)]
#[snafu(visibility(pub))]
#[snafu(display(
    "Protocol error: type = {:?}, description: {:?}",
    error,
    error_description
))]
pub struct ProtocolError {
    error: ErrorType,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl Debug for ProtocolError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        Ok(())
    }
}

impl ProtocolError {
    pub fn error_type(&self) -> &ErrorType {
        &self.error
    }
}

impl ProtocolSnafu<ErrorType, Option<String>> {
    pub fn new(error: ErrorType, description: String) -> Self {
        Self {
            error,
            error_description: Some(description),
        }
    }
}
