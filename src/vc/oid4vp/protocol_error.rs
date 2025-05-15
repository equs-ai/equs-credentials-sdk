use crate::vc::oid4vp::Url;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::fmt::Debug;

pub type ErrorType = openid4vp::core::error::ErrorType;

/// A protocol-specific `oid4vp` error response.
///
/// Those errors are defined in the standard.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response>.
///
/// Should be treated like 400 errors.
///
#[derive(Snafu, Clone, DebugError, Deserialize, Serialize)]
#[snafu(visibility(pub))]
#[snafu(display(
    "Protocol error: type = {}, description: {}",
    error,
    error_description.clone().unwrap_or("".to_string())
))]
pub struct ProtocolError {
    error: ErrorType,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing)]
    redirect_uri: Option<Url>,
}

impl ProtocolError {
    pub fn error_type(&self) -> &ErrorType {
        &self.error
    }

    pub fn description(&self) -> &Option<String> {
        &self.error_description
    }
    pub fn state(&self) -> &Option<String> {
        &self.state
    }

    pub fn set_redirect_uri(&mut self, uri: Option<Url>) {
        self.redirect_uri = uri;
    }

    pub fn redirect_uri(&self) -> Option<&Url> {
        self.redirect_uri.as_ref()
    }

    pub fn new(
        error_type: ErrorType,
        error_description: Option<String>,
        state: Option<String>,
    ) -> Self {
        Self {
            error: error_type,
            error_description,
            state,
            redirect_uri: None,
        }
    }

    pub fn access_denied(message: &str, state: Option<String>) -> ProtocolError {
        ProtocolError::new(ErrorType::AccessDenied, Some(message.to_owned()), state)
    }

    pub fn vp_formats_not_supported(message: &str, state: Option<String>) -> ProtocolError {
        ProtocolError::new(
            ErrorType::VpFormatsNotSupported,
            Some(message.to_owned()),
            state,
        )
    }

    pub fn invalid_request(message: &str, state: Option<String>) -> ProtocolError {
        ProtocolError::new(ErrorType::InvalidRequest, Some(message.to_owned()), state)
    }
}

impl ProtocolSnafu<ErrorType, Option<String>, Option<String>, Option<Url>> {
    pub fn new(error: ErrorType, description: String, state: String) -> Self {
        Self {
            error,
            error_description: Some(description),
            state: Some(state),
            redirect_uri: None,
        }
    }
}
