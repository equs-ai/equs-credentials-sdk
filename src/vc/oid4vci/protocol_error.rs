use oid4vci::credential::RequestError;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::fmt::Debug;
use time::Duration;
use tracing::{instrument, Level};

use crate::http::HttpError;
use crate::nonce::Nonce;
use crate::utils::serde::{duration_to_int, int_to_duration};
use crate::vc::oid4vci::ErrorType;

/// A protocol-specific `oid4vci` error response.
///
/// Those errors are defined in the standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// Should be treated like 4xx errors.
///
/// # Nonce
///
/// `Holder`s MUST use `c_nonce` and `c_nonce_expires_in` for subsequent requests if they're returned.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    c_nonce: Option<Nonce>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "int_to_duration",
        serialize_with = "duration_to_int"
    )]
    c_nonce_expires_in: Option<Duration>,
}

impl Debug for ProtocolError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        Ok(())
    }
}

impl ProtocolError {
    pub fn nonce(&self) -> Option<&Nonce> {
        self.c_nonce.as_ref()
    }

    pub fn nonce_expiration(&self) -> Option<&Duration> {
        self.c_nonce_expires_in.as_ref()
    }

    pub fn error_type(&self) -> &ErrorType {
        &self.error
    }
}

impl ProtocolSnafu<ErrorType, Option<String>, Option<Nonce>, Option<Duration>> {
    pub fn new(error: ErrorType, description: String) -> Self {
        Self {
            error,
            error_description: Some(description),
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    }

    pub fn new_with_nonce(
        error: ErrorType,
        description: &str,
        nonce: &Nonce,
        nonce_expires_in: &Option<Duration>,
    ) -> Self {
        Self {
            error,
            error_description: Some(description.to_owned()),
            c_nonce: Some(nonce.to_owned()),
            c_nonce_expires_in: nonce_expires_in.to_owned(),
        }
    }
}

impl TryFrom<RequestError<HttpError>> for ProtocolError {
    type Error = RequestError<HttpError>;

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    fn try_from(value: RequestError<HttpError>) -> Result<Self, Self::Error> {
        match &value {
            RequestError::Response(_, body, _) => {
                serde_json::from_slice::<ProtocolError>(body.as_slice()).map_err(|_| value)
            }
            RequestError::ProofVerification(body) => {
                let protocol_error = match &body.c_nonce {
                    Some(nonce) => ProtocolSnafu::new_with_nonce(
                        ErrorType::InvalidProof,
                        &body.error_description,
                        &Nonce(nonce.secret().to_owned()),
                        &body.c_nonce_expires_in.map(Duration::seconds),
                    )
                    .build(),
                    _ => ProtocolSnafu::new(
                        ErrorType::InvalidProof,
                        body.error_description.to_owned(),
                    )
                    .build(),
                };

                Ok(protocol_error)
            }
            _ => Err(value),
        }
    }
}
