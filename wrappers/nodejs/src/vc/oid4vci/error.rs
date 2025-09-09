use crate::error::{EncodableError, IntoNapiError};
use agent_sdk::vc::oid4vci::{
    CredentialOfferResolverError, ErrorType, InternalError, ProtocolError,
};
use napi::Error;
use napi_derive::napi;
use strum_macros::Display;

impl IntoNapiError for agent_sdk::vc::oid4vci::Error {
    fn into_napi_error(self) -> Error {
        match self {
            agent_sdk::vc::oid4vci::Error::Internal { source: err, .. } => err.into_napi_error(),
            agent_sdk::vc::oid4vci::Error::Protocol { source: err, .. } => err.into_napi_error(),
            _ => Error::from_reason(self.to_string()),
        }
    }
}

impl From<InternalError> for EncodableError {
    fn from(value: InternalError) -> Self {
        let code = match value {
            InternalError::CredDefNotFound { .. } => JsInternalError::CredDefNotFound,
            InternalError::NoScopeSet { .. } => JsInternalError::NoScopeSet,
            InternalError::ClaimsValidation { .. } => JsInternalError::ClaimsValidation,
            InternalError::IssuerService { .. } => JsInternalError::IssuerService,
            InternalError::HolderService { .. } => JsInternalError::HolderService,
            InternalError::UrlParse { .. } => JsInternalError::UrlParse,
            InternalError::Parse { .. } => JsInternalError::Parse,
            InternalError::Storage { .. } => JsInternalError::Storage,
            InternalError::VC { .. } => JsInternalError::VC,
            InternalError::Vault { .. } => JsInternalError::Vault,
            InternalError::Request { .. } => JsInternalError::Request,
            InternalError::Discovery { .. } => JsInternalError::Discovery,
            InternalError::HttpClient { .. } => JsInternalError::HttpClient,
            InternalError::Metadata { .. } => JsInternalError::Metadata,
            InternalError::NonceHandler { .. } => JsInternalError::NonceHandler,
            InternalError::TypeConversion { .. } => JsInternalError::TypeConversion,
            InternalError::AuthorizationCallback { .. } => JsInternalError::AuthorizationCallback,
        };
        Self::new(code.to_string(), value.to_string())
    }
}

#[napi(string_enum, js_name=VciInternalError)]
#[derive(Display)]
pub enum JsInternalError {
    CredDefNotFound,
    NoScopeSet,
    ClaimsValidation,
    IssuerService,
    HolderService,
    UrlParse,
    Parse,
    Storage,
    VC,
    Vault,
    Request,
    Discovery,
    HttpClient,
    Metadata,
    NonceHandler,
    TypeConversion,
    AuthorizationCallback,
}

impl From<ProtocolError> for EncodableError {
    fn from(value: ProtocolError) -> Self {
        let code = match value.error_type() {
            ErrorType::InvalidToken => JsProtocolError::InvalidToken,
            ErrorType::InvalidCredentialRequest => JsProtocolError::InvalidCredentialRequest,
            ErrorType::UnknownCredentialConfiguration => {
                JsProtocolError::UnknownCredentialConfiguration
            }
            ErrorType::UnknownCredentialIdentifier => JsProtocolError::UnknownCredentialIdentifier,
            ErrorType::InvalidProof => JsProtocolError::InvalidProof,
            ErrorType::InvalidEncryptionParameters => JsProtocolError::InvalidEncryptionParameters,
            ErrorType::InvalidNonce => JsProtocolError::InvalidNonce,
            ErrorType::CredentialRequestDenied => JsProtocolError::CredentialRequestDenied,
            ErrorType::InvalidRequest => JsProtocolError::InvalidRequest,
            ErrorType::InsufficientScope => JsProtocolError::InsufficientScope,
        };
        Self::new(code.to_string(), value.to_string())
    }
}

#[napi(string_enum, js_name=VciProtocolError)]
#[derive(Display)]
pub enum JsProtocolError {
    InvalidToken,
    InvalidCredentialRequest,
    UnknownCredentialConfiguration,
    UnknownCredentialIdentifier,
    InvalidProof,
    InvalidEncryptionParameters,
    InvalidNonce,
    CredentialRequestDenied,
    InvalidRequest,
    InsufficientScope,
}

impl From<CredentialOfferResolverError> for EncodableError {
    fn from(value: CredentialOfferResolverError) -> Self {
        let code = match value {
            CredentialOfferResolverError::Resolve { .. } => JsCredentialOfferResolverError::Resolve,
            CredentialOfferResolverError::HttpClient { .. } => {
                JsCredentialOfferResolverError::HttpClient
            }
        };
        Self::new(code.to_string(), value.to_string())
    }
}

#[napi(string_enum, js_name=CredentialOfferResolverError)]
#[derive(Display)]
pub enum JsCredentialOfferResolverError {
    Resolve,
    HttpClient,
}
