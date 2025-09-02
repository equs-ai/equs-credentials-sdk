use crate::error::EncodableError;
use agent_sdk::vc::core::Error as CoreError;
use napi_derive::napi;
use strum_macros::Display;

impl From<CoreError> for EncodableError {
    fn from(value: CoreError) -> Self {
        let code = match value {
            CoreError::CredDefNotFound { .. } => JsError::CredDefNotFound,
            CoreError::ClaimsNotFound { .. } => JsError::ClaimsNotFound,
            CoreError::ProofFormatRequired => JsError::ProofFormatRequired,
            CoreError::RequestedCredentialNotFound { .. } => JsError::RequestedCredentialNotFound,
            CoreError::InconsistentProtocolData { .. } => JsError::InconsistentProtocolData,
            CoreError::FormatNotSupported { .. } => JsError::FormatNotSupported,
            CoreError::AlgNotSupported { .. } => JsError::AlgNotSupported,
            CoreError::ProofFormatNotSupported { .. } => JsError::ProofFormatNotSupported,
            CoreError::InvalidDIDUrl { .. } => JsError::InvalidDIDUrl,
            CoreError::VC { .. } => JsError::VC,
            CoreError::Proof { .. } => JsError::Proof,
            CoreError::KMS { .. } => JsError::KMS,
            CoreError::Vault { .. } => JsError::Vault,
            CoreError::Parse { .. } => JsError::Parse,
            CoreError::Claims { .. } => JsError::Claims,
            CoreError::ContextParsing { .. } => JsError::ContextParsing,
            CoreError::VCStatus { .. } => JsError::VCStatus,
            CoreError::StatusListNotProvided => JsError::StatusListNotProvided,
            CoreError::CredentialStatusNotSupported => JsError::CredentialStatusNotSupported,
            CoreError::CredentialStatusProtocolNotSupported { .. } => {
                JsError::CredentialStatusProtocolNotSupported
            }
            CoreError::StatusListCreating { .. } => JsError::StatusListCreating,
            CoreError::InconsistentStatusListData { .. } => JsError::InconsistentStatusListData,
            CoreError::CannotCreateRegex { .. } => JsError::CannotCreateRegex,
            CoreError::ClaimsDidNotPassFiltering { .. } => JsError::ClaimsDidNotPassFiltering,
            CoreError::CredentialExpired => JsError::CredentialExpired,
            CoreError::ExpirationCheck { .. } => JsError::ExpirationCheck,
            CoreError::VCNotValid { .. } => JsError::VCNotValid,
        };
        Self::new(code.to_string(), value.to_string())
    }
}

#[napi(string_enum, js_name=CoreError)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Display)]
pub enum JsError {
    CredDefNotFound,
    ClaimsNotFound,
    ProofFormatRequired,
    RequestedCredentialNotFound,
    InconsistentProtocolData,
    FormatNotSupported,
    AlgNotSupported,
    ProofFormatNotSupported,
    InvalidDIDUrl,
    VC,
    Proof,
    KMS,
    Vault,
    Parse,
    Claims,
    ContextParsing,
    VCStatus,
    StatusListNotProvided,
    CredentialStatusNotSupported,
    CredentialStatusProtocolNotSupported,
    StatusListCreating,
    InconsistentStatusListData,
    CannotCreateRegex,
    ClaimsDidNotPassFiltering,
    CredentialExpired,
    ExpirationCheck,
    VCNotValid,
}
