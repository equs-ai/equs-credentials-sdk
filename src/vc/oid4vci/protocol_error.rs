use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::fmt::Debug;

pub type CredentialEndpointError = oid4vci::credential::ErrorType;
pub type TokenEndpointError = oauth2::basic::BasicErrorResponseType;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOfferEndpointError {
    InvalidRequest,
    UnknownCredentialIdentifier,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ErrorType {
    CredentialOfferEndpoint(CredentialOfferEndpointError),
    CredentialEndpoint(CredentialEndpointError),
    TokenEndpoint(TokenEndpointError),
}

/// A protocol-specific `oid4vci` error response.
///
/// Those errors are defined in the standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// Should be treated like 4xx errors.
#[derive(Snafu, Clone, Deserialize, Serialize)]
#[snafu(visibility(pub))]
#[snafu(display(
    "Protocol error: type {}: {}",
    serde_json::to_string(&self.error).unwrap_or_default(),
    error_description.clone().unwrap_or_default()
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
    pub fn new(error: ErrorType, error_description: Option<String>) -> Self {
        Self {
            error,
            error_description,
        }
    }
    pub fn error_type(&self) -> &ErrorType {
        &self.error
    }

    pub fn error_description(&self) -> Option<&String> {
        self.error_description.as_ref()
    }
}

impl ProtocolSnafu<ErrorType, Option<String>> {
    pub fn credential_endpoint(error: CredentialEndpointError, description: String) -> Self {
        Self {
            error: ErrorType::CredentialEndpoint(error),
            error_description: Some(description),
        }
    }

    pub fn credential_offer_endpoint(
        error: CredentialOfferEndpointError,
        description: String,
    ) -> Self {
        Self {
            error: ErrorType::CredentialOfferEndpoint(error),
            error_description: Some(description),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_error_new_stores_all_fields() {
        let e = ProtocolError::new(
            ErrorType::CredentialOfferEndpoint(CredentialOfferEndpointError::InvalidRequest),
            Some("bad request".to_string()),
        );
        assert!(matches!(
            e.error_type(),
            ErrorType::CredentialOfferEndpoint(CredentialOfferEndpointError::InvalidRequest)
        ));
        assert_eq!(e.error_description(), Some(&"bad request".to_string()));
    }

    #[test]
    fn protocol_error_new_without_description() {
        let e = ProtocolError::new(
            ErrorType::CredentialOfferEndpoint(
                CredentialOfferEndpointError::UnknownCredentialIdentifier,
            ),
            None,
        );
        assert_eq!(e.error_description(), None);
    }

    #[test]
    fn protocol_error_display_contains_type_and_description() {
        let e = ProtocolError::new(
            ErrorType::CredentialOfferEndpoint(CredentialOfferEndpointError::InvalidRequest),
            Some("missing field".to_string()),
        );
        let s = format!("{e}");
        assert!(s.contains("Protocol error"));
        assert!(s.contains("missing field"));
    }

    #[test]
    fn credential_offer_endpoint_snafu_convenience_constructor() {
        let result: Result<(), ProtocolError> = ProtocolSnafu::credential_offer_endpoint(
            CredentialOfferEndpointError::UnknownCredentialIdentifier,
            "no such credential".to_string(),
        )
        .fail();
        let e = result.unwrap_err();
        assert!(matches!(
            e.error_type(),
            ErrorType::CredentialOfferEndpoint(
                CredentialOfferEndpointError::UnknownCredentialIdentifier
            )
        ));
        assert_eq!(
            e.error_description(),
            Some(&"no such credential".to_string())
        );
    }

    #[test]
    fn credential_endpoint_snafu_convenience_constructor() {
        let result: Result<(), ProtocolError> = ProtocolSnafu::credential_endpoint(
            CredentialEndpointError::InvalidProof,
            "bad proof".to_string(),
        )
        .fail();
        let e = result.unwrap_err();
        assert!(matches!(
            e.error_type(),
            ErrorType::CredentialEndpoint(CredentialEndpointError::InvalidProof)
        ));
    }

    #[test]
    fn credential_offer_endpoint_error_serde_roundtrip() {
        for case in [
            CredentialOfferEndpointError::InvalidRequest,
            CredentialOfferEndpointError::UnknownCredentialIdentifier,
        ] {
            let json = serde_json::to_value(&case).unwrap();
            let back: CredentialOfferEndpointError = serde_json::from_value(json).unwrap();
            assert_eq!(back, case);
        }
    }
}
