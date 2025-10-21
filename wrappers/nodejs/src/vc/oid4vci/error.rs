use crate::error::{EncodableError, IntoNapiError};
use agent_sdk::vc::oid4vci::{
    CredentialOfferResolverError, InternalError, ProtocolError, ProtocolErrorCredentialEndpoint,
    ProtocolErrorCredentialOfferEndpoint, ProtocolErrorTokenEndpoint, ProtocolErrorType,
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
            InternalError::TokenRequest { .. } => JsInternalError::TokenRequest,
            InternalError::AuthorizationRequest { .. } => JsInternalError::AuthorizationRequest,
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
    AuthorizationRequest,
    TokenRequest,
}

impl From<ProtocolError> for EncodableError {
    fn from(value: ProtocolError) -> Self {
        let code = match value.error_type() {
            // Credential Endpoint Errors
            ProtocolErrorType::CredentialEndpoint(err) => match err {
                ProtocolErrorCredentialEndpoint::InvalidToken => {
                    JsProtocolError::CredentialEndpointInvalidToken
                }
                ProtocolErrorCredentialEndpoint::InvalidCredentialRequest => {
                    JsProtocolError::CredentialEndpointInvalidCredentialRequest
                }
                ProtocolErrorCredentialEndpoint::InvalidRequest => {
                    JsProtocolError::CredentialEndpointInvalidRequest
                }
                ProtocolErrorCredentialEndpoint::UnknownCredentialConfiguration => {
                    JsProtocolError::CredentialEndpointUnknownCredentialConfiguration
                }
                ProtocolErrorCredentialEndpoint::UnknownCredentialIdentifier => {
                    JsProtocolError::CredentialEndpointUnknownCredentialIdentifier
                }
                ProtocolErrorCredentialEndpoint::InvalidProof => {
                    JsProtocolError::CredentialEndpointInvalidProof
                }
                ProtocolErrorCredentialEndpoint::InvalidEncryptionParameters => {
                    JsProtocolError::CredentialEndpointInvalidEncryptionParameters
                }
                ProtocolErrorCredentialEndpoint::InvalidNonce => {
                    JsProtocolError::CredentialEndpointInvalidNonce
                }
                ProtocolErrorCredentialEndpoint::CredentialRequestDenied => {
                    JsProtocolError::CredentialEndpointCredentialRequestDenied
                }
                ProtocolErrorCredentialEndpoint::InsufficientScope => {
                    JsProtocolError::CredentialEndpointInsufficientScope
                }
            },
            // Credential Offer Endpoint Errors
            ProtocolErrorType::CredentialOfferEndpoint(err) => match err {
                ProtocolErrorCredentialOfferEndpoint::InvalidRequest => {
                    JsProtocolError::CredentialOfferEndpointInvalidRequest
                }
                ProtocolErrorCredentialOfferEndpoint::UnknownCredentialIdentifier => {
                    JsProtocolError::CredentialOfferEndpointUnknownCredentialIdentifier
                }
            },
            // Token Endpoint Errors
            ProtocolErrorType::TokenEndpoint(err) => match err {
                ProtocolErrorTokenEndpoint::InvalidClient => {
                    JsProtocolError::TokenEndpointInvalidClient
                }
                ProtocolErrorTokenEndpoint::InvalidGrant => {
                    JsProtocolError::TokenEndpointInvalidGrant
                }
                ProtocolErrorTokenEndpoint::InvalidRequest => {
                    JsProtocolError::TokenEndpointInvalidRequest
                }
                ProtocolErrorTokenEndpoint::InvalidScope => {
                    JsProtocolError::TokenEndpointInvalidScope
                }
                ProtocolErrorTokenEndpoint::UnauthorizedClient => {
                    JsProtocolError::TokenEndpointUnauthorizedClient
                }
                ProtocolErrorTokenEndpoint::UnsupportedGrantType => {
                    JsProtocolError::TokenEndpointUnsupportedGrantType
                }
                ProtocolErrorTokenEndpoint::Extension(_) => JsProtocolError::TokenEndpointExtension,
            },
        };
        Self::new(code.to_string(), value.to_string())
    }
}

#[napi(string_enum, js_name=VciProtocolError)]
#[derive(Display)]
pub enum JsProtocolError {
    // Credential Endpoint Errors
    CredentialEndpointInvalidToken,
    CredentialEndpointInvalidCredentialRequest,
    CredentialEndpointUnknownCredentialConfiguration,
    CredentialEndpointUnknownCredentialIdentifier,
    CredentialEndpointInvalidProof,
    CredentialEndpointInvalidEncryptionParameters,
    CredentialEndpointInvalidNonce,
    CredentialEndpointCredentialRequestDenied,
    CredentialEndpointInvalidRequest,
    CredentialEndpointInsufficientScope,

    // Credential Endpoint Errors
    CredentialOfferEndpointInvalidRequest,
    CredentialOfferEndpointUnknownCredentialIdentifier,

    // Token Endpoint Errors
    TokenEndpointInvalidClient,
    TokenEndpointInvalidGrant,
    TokenEndpointInvalidRequest,
    TokenEndpointInvalidScope,
    TokenEndpointUnauthorizedClient,
    TokenEndpointUnsupportedGrantType,
    TokenEndpointExtension,
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
