pub mod builder;
pub mod credential_offer_resolver;
pub mod holder;
pub mod issuer;

use crate::result::IntoNapiError;
use crate::vc::oid4vci::builder::TokenValidation;
use agent_sdk::vc::oid4vci::{
    CredentialOfferResolverError, ErrorType, InternalError, ProtocolError,
};
use napi::Error;
use napi_derive::napi;
use time::Duration;

impl IntoNapiError for agent_sdk::vc::oid4vci::Error {
    fn into_napi_error(self) -> Error {
        match self {
            agent_sdk::vc::oid4vci::Error::Internal { source: err, .. } => err.into_napi_error(),
            agent_sdk::vc::oid4vci::Error::Protocol { source: err, .. } => err.into_napi_error(),
            _ => Error::from_reason(self.to_string()),
        }
    }
}

impl IntoNapiError for InternalError {
    fn into_napi_error(self) -> Error {
        let error_code = match self {
            Self::CredDefNotFound { .. } => "CredDefNotFound",
            Self::NoScopeSet { .. } => "NoScopeSet",
            Self::ClaimsValidation { .. } => "ClaimsValidation",
            Self::IssuerService { .. } => "IssuerService",
            Self::HolderService { .. } => "HolderService",
            Self::UrlParse { .. } => "UrlParse",
            Self::Parse { .. } => "Parse",
            Self::Storage { .. } => "Storage",
            Self::VC { .. } => "VC",
            Self::Vault { .. } => "Vault",
            Self::Request { .. } => "Request",
            Self::Discovery { .. } => "Discovery",
            Self::HttpClient { .. } => "HttpClient",
            Self::Metadata { .. } => "Metadata",
            Self::NonceHandler { .. } => "NonceHandler",
            Self::TypeConversion { .. } => "TypeConversion",
            Self::AuthorizationCallback { .. } => "AuthorizationCallback",
            _ => "InternalError",
        };
        Error::from_reason(error_code)
    }
}

impl IntoNapiError for ProtocolError {
    fn into_napi_error(self) -> Error {
        let error_code = match self.error_type() {
            ErrorType::InvalidToken => "InvalidToken",
            ErrorType::InvalidCredentialRequest => "InvalidCredentialRequest",
            ErrorType::UnsupportedCredentialType => "UnsupportedCredentialType",
            ErrorType::UnsupportedCredentialFormat => "UnsupportedCredentialFormat",
            ErrorType::InvalidProof => "InvalidProof",
            ErrorType::InvalidEncryptionParameters => "InvalidEncryptionParameters",
        };
        Error::from_reason(error_code)
    }
}

impl IntoNapiError for CredentialOfferResolverError {
    fn into_napi_error(self) -> Error {
        let error_code = match self {
            CredentialOfferResolverError::Resolve { .. } => "Resolve",
            CredentialOfferResolverError::HttpClient { .. } => "HttpClient",
            _ => "Unknown",
        };
        Error::from_reason(error_code)
    }
}

#[napi(js_name = "TokenValidationEnum")]
pub enum JsTokenValidationEnum {
    Introspect,
    Jwks,
}

#[napi(js_name = "TokenValidation", object)]
pub struct JsTokenValidation {
    pub type_: JsTokenValidationEnum,
    pub url: String,
    pub header: Option<String>,
}

impl TryFrom<TokenValidation> for JsTokenValidation {
    type Error = Error;

    fn try_from(value: TokenValidation) -> Result<Self, Error> {
        match value {
            TokenValidation::Introspect(url, header) => Ok(JsTokenValidation {
                type_: JsTokenValidationEnum::Introspect,
                url,
                header,
            }),

            TokenValidation::Jwks(url) => Ok(JsTokenValidation {
                type_: JsTokenValidationEnum::Jwks,
                url,
                header: None,
            }),
        }
    }
}

impl TryFrom<JsTokenValidation> for TokenValidation {
    type Error = Error;

    fn try_from(value: JsTokenValidation) -> Result<Self, Error> {
        let result = match value.type_ {
            JsTokenValidationEnum::Introspect => {
                TokenValidation::Introspect(value.url, value.header)
            }
            JsTokenValidationEnum::Jwks => TokenValidation::Jwks(value.url),
        };
        Ok(result)
    }
}

#[napi(js_name = "Duration", object)]
pub struct JsDuration {
    pub seconds: i64,
    pub nanoseconds: i32,
}

impl From<Duration> for JsDuration {
    fn from(duration: Duration) -> Self {
        JsDuration {
            seconds: duration.whole_seconds(),
            nanoseconds: duration.subsec_nanoseconds(),
        }
    }
}

impl TryFrom<JsDuration> for Duration {
    type Error = Error;

    fn try_from(js_duration: JsDuration) -> Result<Self, Error> {
        Ok(Duration::new(js_duration.seconds, js_duration.nanoseconds))
    }
}
