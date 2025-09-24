use crate::error::{EncodableError, IntoNapiError};
use agent_sdk::vc::oid4vp::{Error, ErrorType, InternalError, ProtocolError};
use napi_derive::napi;
use strum_macros::Display;

impl IntoNapiError for Error {
    fn into_napi_error(self) -> napi::Error {
        match self {
            Error::Internal { source: e } => e.into_napi_error(),
            Error::Protocol { source: e } => e.into_napi_error(),
            _ => napi::Error::from_reason(self.to_string()),
        }
    }
}

impl From<InternalError> for EncodableError {
    fn from(value: InternalError) -> Self {
        let code = match value {
            InternalError::AuthorizationResponse { .. } => JsInternalError::AuthorizationResponse,
            InternalError::AuthorizationResponseUnsupportedMode { .. } => {
                JsInternalError::AuthorizationResponseUnsupportedMode
            }
            InternalError::AuthorizationResponseDecryption { .. } => {
                JsInternalError::AuthorizationResponseDecryption
            }
            InternalError::CredentialNotFound => JsInternalError::CredentialNotFound,
            InternalError::IdTokenMetadataNotFound => JsInternalError::IdTokenMetadataNotFound,
            InternalError::IdTokenParse { .. } => JsInternalError::IdTokenParse,
            InternalError::IdTokenValidation { .. } => JsInternalError::IdTokenValidation,
            InternalError::IdTokenGeneration { .. } => JsInternalError::IdTokenGeneration,
            InternalError::FormatNotSupported { .. } => JsInternalError::FormatNotSupported,
            InternalError::KMS { .. } => JsInternalError::KMS,
            InternalError::Oid4VpLib { .. } => JsInternalError::Oid4VpLib,
            InternalError::JWS { .. } => JsInternalError::JWS,
            InternalError::Json { .. } => JsInternalError::Json,
            InternalError::Parse { .. } => JsInternalError::Parse,
            InternalError::VC { .. } => JsInternalError::VC,
            InternalError::VCStatus { .. } => JsInternalError::VCStatus,
            InternalError::VCNotValid { .. } => JsInternalError::VCNotValid,
            InternalError::UrlParse { .. } => JsInternalError::UrlParse,
            InternalError::PresentationExchange { .. } => JsInternalError::PresentationExchange,
            InternalError::DCQL { .. } => JsInternalError::DCQL,
            InternalError::HttpClient { .. } => JsInternalError::HttpClient,
            InternalError::NonceGeneration { .. } => JsInternalError::NonceGeneration,
            InternalError::Claims { .. } => JsInternalError::Claims,
            InternalError::DidUrlResolution { .. } => JsInternalError::DidUrlResolution,
            InternalError::JWE { .. } => JsInternalError::JWE,
            InternalError::Client { .. } => JsInternalError::Client,
            InternalError::TransactionData { .. } => JsInternalError::TransactionData,
        };
        Self::new(code.to_string(), value.to_string())
    }
}

#[napi(string_enum, js_name = "VpInternalError")]
#[derive(Display)]
pub enum JsInternalError {
    AuthorizationResponse,
    AuthorizationResponseUnsupportedMode,
    AuthorizationResponseDecryption,
    CredentialNotFound,
    IdTokenMetadataNotFound,
    IdTokenParse,
    IdTokenValidation,
    IdTokenGeneration,
    FormatNotSupported,
    KMS,
    Oid4VpLib,
    JWS,
    Json,
    Parse,
    VC,
    VCStatus,
    VCNotValid,
    UrlParse,
    PresentationExchange,
    DCQL,
    HttpClient,
    NonceGeneration,
    Claims,
    DidUrlResolution,
    JWE,
    Client,
    TransactionData,
}

impl From<ProtocolError> for EncodableError {
    fn from(value: ProtocolError) -> Self {
        let code = match value.error_type() {
            ErrorType::InvalidScope => JsProtocolError::InvalidScope,
            ErrorType::InvalidRequest => JsProtocolError::InvalidRequest,
            ErrorType::InvalidClient => JsProtocolError::InvalidClient,
            ErrorType::AccessDenied => JsProtocolError::AccessDenied,
            ErrorType::VpFormatsNotSupported => JsProtocolError::VpFormatsNotSupported,
            ErrorType::InvalidPresentationDefinitionUri => {
                JsProtocolError::InvalidPresentationDefinitionUri
            }
            ErrorType::InvalidPresentationDefinitionReference => {
                JsProtocolError::InvalidPresentationDefinitionReference
            }
            ErrorType::InvalidPresentationDefinitionFormat => {
                JsProtocolError::InvalidPresentationDefinitionFormat
            }
            ErrorType::InvalidRequestUriMethod => JsProtocolError::InvalidRequestUriMethod,
            ErrorType::WalletUnavailable => JsProtocolError::WalletUnavailable,
            ErrorType::InvalidDCQLFormat => JsProtocolError::InvalidDCQLFormat,
            ErrorType::ClientIDPrefixNotGiven => JsProtocolError::ClientIDPrefixNotGiven,
            ErrorType::WrongClientIdPrefix => JsProtocolError::WrongClientIdPrefix,
            ErrorType::InvalidTransactionData => JsProtocolError::InvalidTransactionData,
        };
        Self::new(code.to_string(), value.to_string())
    }
}

#[napi(string_enum, js_name = "VpProtocolError")]
#[derive(Display)]
pub enum JsProtocolError {
    InvalidScope,
    InvalidRequest,
    InvalidClient,
    AccessDenied,
    VpFormatsNotSupported,
    InvalidPresentationDefinitionUri,
    InvalidPresentationDefinitionReference,
    InvalidPresentationDefinitionFormat,
    InvalidRequestUriMethod,
    WalletUnavailable,
    InvalidDCQLFormat,
    ClientIDPrefixNotGiven,
    WrongClientIdPrefix,
    InvalidTransactionData,
}
