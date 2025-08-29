use crate::result::IntoNapiError;
use agent_sdk::vc::oid4vp::{Error, ErrorType, InternalError, ProtocolError};

pub mod builder;
pub mod holder;
pub mod verifier;

impl IntoNapiError for Error {
    fn into_napi_error(self) -> napi::Error {
        match self {
            Error::Internal { source: e } => e.into_napi_error(),
            Error::Protocol { source: e } => e.into_napi_error(),
            _ => napi::Error::from_reason(self.to_string()),
        }
    }
}

impl IntoNapiError for InternalError {
    fn into_napi_error(self) -> napi::Error {
        let error_code = match self {
            Self::AuthorizationResponse { .. } => "AuthorizationResponse",
            Self::AuthorizationResponseUnsupportedMode { .. } => {
                "AuthorizationResponseUnsupportedMode"
            }
            Self::AuthorizationResponseDecryption { .. } => "AuthorizationResponseDecryption",
            Self::CredentialNotFound => "CredentialNotFound",
            Self::IdTokenMetadataNotFound => "IdTokenMetadataNotFound",
            Self::IdTokenParse { .. } => "IdTokenParse",
            Self::IdTokenValidation { .. } => "IdTokenValidation",
            Self::IdTokenGeneration { .. } => "IdTokenGeneration",
            Self::FormatNotSupported { .. } => "FormatNotSupported",
            Self::KMS { .. } => "KMS",
            Self::Oid4VpLib { .. } => "Oid4VpLib",
            Self::JWS { .. } => "JWS",
            Self::Json { .. } => "Json",
            Self::Parse { .. } => "Parse",
            Self::VC { .. } => "VC",
            Self::VCStatus { .. } => "VCStatus",
            Self::VCNotValid { .. } => "VCNotValid",
            Self::UrlParse { .. } => "UrlParse",
            Self::PresentationExchange { .. } => "PresentationExchange",
            Self::DCQL { .. } => "DCQL",
            Self::HttpClient { .. } => "HttpClient",
            Self::NonceGeneration { .. } => "NonceGeneration",
            Self::Claims { .. } => "Claims",
            Self::DidUrlResolution { .. } => "DidUrlResolution",
            Self::JWE { .. } => "JWE",
            Self::ClientId { .. } => "ClientId",
            _ => "Unknown",
        };
        napi::Error::from_reason(error_code)
    }
}

impl IntoNapiError for ProtocolError {
    fn into_napi_error(self) -> napi::Error {
        let error_code = match self.error_type() {
            ErrorType::InvalidScope => "InvalidScope",
            ErrorType::InvalidRequest => "InvalidRequest",
            ErrorType::InvalidClient => "InvalidClient",
            ErrorType::AccessDenied => "AccessDenied",
            ErrorType::VpFormatsNotSupported => "VpFormatsNotSupported",
            ErrorType::InvalidPresentationDefinitionUri => "InvalidPresentationDefinitionUri",
            ErrorType::InvalidPresentationDefinitionReference => {
                "InvalidPresentationDefinitionReference"
            }
            ErrorType::InvalidPresentationDefinitionFormat => "InvalidPresentationDefinitionFormat",
            ErrorType::InvalidRequestUriMethod => "InvalidRequestUriMethod",
            ErrorType::WalletUnavailable => "WalletUnavailable",
            ErrorType::InvalidDCQLFormat => "InvalidDCQLFormat",
            ErrorType::ClientIDSchemeNotGiven => "ClientIDSchemeNotGiven",
            ErrorType::WrongClientIdScheme => "WrongClientIdScheme",
        };
        napi::Error::from_reason(error_code)
    }
}
