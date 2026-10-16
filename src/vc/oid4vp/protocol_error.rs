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

    pub fn transaction_data(message: &str, state: Option<String>) -> ProtocolError {
        ProtocolError::new(
            ErrorType::InvalidTransactionData,
            Some(message.to_owned()),
            state,
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_error_new_stores_all_fields() {
        let e = ProtocolError::new(
            ErrorType::AccessDenied,
            Some("denied".to_string()),
            Some("abc".to_string()),
        );
        assert!(matches!(e.error_type(), ErrorType::AccessDenied));
        assert_eq!(e.description(), &Some("denied".to_string()));
        assert_eq!(e.state(), &Some("abc".to_string()));
        assert!(e.redirect_uri().is_none());
    }

    #[test]
    fn access_denied_sets_error_type_and_description() {
        let e = ProtocolError::access_denied("user rejected", Some("s1".to_string()));
        assert!(matches!(e.error_type(), ErrorType::AccessDenied));
        assert_eq!(e.description(), &Some("user rejected".to_string()));
        assert_eq!(e.state(), &Some("s1".to_string()));
    }

    #[test]
    fn invalid_request_sets_error_type_and_description() {
        let e = ProtocolError::invalid_request("missing nonce", None);
        assert!(matches!(e.error_type(), ErrorType::InvalidRequest));
        assert_eq!(e.description(), &Some("missing nonce".to_string()));
        assert_eq!(e.state(), &None);
    }

    #[test]
    fn redirect_uri_getter_and_setter() {
        let mut e = ProtocolError::access_denied("msg", None);
        assert!(e.redirect_uri().is_none());

        let url: Url = "https://example.com/cb".parse().unwrap();
        e.set_redirect_uri(Some(url.clone()));
        assert_eq!(e.redirect_uri(), Some(&url));

        e.set_redirect_uri(None);
        assert!(e.redirect_uri().is_none());
    }

    #[test]
    fn protocol_error_display_contains_error_type() {
        let e = ProtocolError::access_denied("forbidden", None);
        let s = format!("{e}");
        assert!(s.contains("Protocol error"));
    }

    #[test]
    fn protocol_error_display_without_description() {
        let e = ProtocolError::new(ErrorType::InvalidRequest, None, None);
        let s = format!("{e}");
        assert!(s.contains("Protocol error"));
    }
}
