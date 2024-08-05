#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("Authorization Request creation failed: {0}")]
    RequestCreationFailed(String),
    #[error("Invalid Authorization Response: {0}")]
    InvalidResponse(String),
    #[error("Key resolution failed: {0}")]
    KeyResolutionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("{0} format not supported")]
    FormatNotSupported(String),
    #[error("Presentation verification failed {0}")]
    VerificationFailed(String),
    #[error("Failed to parse: {0}")]
    ParsingError(String),
    #[error("Required field missing: {0}")]
    MissingRequiredField(String),
}