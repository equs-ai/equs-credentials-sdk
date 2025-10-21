use agent_sdk::vc::VCFormat;
use agent_sdk::vc::oid4vp::{
    CredentialsFindResult as ASDKCredentialsSearchResult, FindVCsFailReason,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

mod oid4vci;
mod oid4vp;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Credential")]
    pub type Credential;

    #[wasm_bindgen(typescript_type = "CredentialEntry")]
    pub type CredentialEntry;

    #[wasm_bindgen(typescript_type = "CredentialMetadata")]
    pub type CredentialMetadata;

    #[wasm_bindgen(typescript_type = "VaultPagination")]
    pub type VaultPagination;

    #[wasm_bindgen(typescript_type = "CredentialsFindResult")]
    pub type JsCredentialsFindResult;

    #[wasm_bindgen(typescript_type = "CredentialExtraVerification")]
    pub type CredentialExtraVerification;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsCredential {
    format: VCFormat,
    payload: String,
}

impl TryFrom<agent_sdk::vc::Credential> for JsCredential {
    type Error = JsError;
    fn try_from(value: agent_sdk::vc::Credential) -> Result<Self, JsError> {
        let js_credential = match value {
            agent_sdk::vc::Credential::SdJwt(payload) => JsCredential {
                format: VCFormat::SdJwtVc,
                payload,
            },
            agent_sdk::vc::Credential::LdpVc(payload) => JsCredential {
                format: VCFormat::LdpVc,
                payload: serde_json::to_string(&payload)?,
            },
            agent_sdk::vc::Credential::JwtVcJson(payload) => JsCredential {
                format: VCFormat::JwtVcJson,
                payload,
            },
            agent_sdk::vc::Credential::JwtVcJsonLd(payload) => JsCredential {
                format: VCFormat::JwtVcJsonLD,
                payload,
            },
            _ => Err(JsError::new("Unsupported VC format"))?,
        };

        Ok(js_credential)
    }
}

impl TryFrom<JsCredential> for agent_sdk::vc::Credential {
    type Error = JsError;

    fn try_from(value: JsCredential) -> Result<Self, JsError> {
        match value.format {
            VCFormat::JwtVcJson => Ok(agent_sdk::vc::Credential::JwtVcJson(value.payload)),
            VCFormat::JwtVcJsonLD => Ok(agent_sdk::vc::Credential::JwtVcJsonLd(value.payload)),
            VCFormat::LdpVc => Ok(agent_sdk::vc::Credential::LdpVc(serde_json::from_str(
                &value.payload,
            )?)),
            VCFormat::SdJwtVc => Ok(agent_sdk::vc::Credential::SdJwt(value.payload)),
            VCFormat::MsoMdoc => Err(JsError::new("Unsupported VC format: MsoDoc")),
            _ => Err(JsError::new("Unsupported VC format"))?,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsCredentialEntry {
    credential: JsCredential,
    kid: String,
    id: String,
}

impl TryFrom<agent_sdk::vault::CredentialEntry> for JsCredentialEntry {
    type Error = JsError;

    fn try_from(value: agent_sdk::vault::CredentialEntry) -> Result<Self, JsError> {
        Ok(JsCredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

impl TryFrom<JsCredentialEntry> for agent_sdk::vault::CredentialEntry {
    type Error = JsError;

    fn try_from(value: JsCredentialEntry) -> Result<Self, JsError> {
        Ok(agent_sdk::vault::CredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum JsFindVCsFailReasonType {
    Paths,
    TypesNotMatched,
    CredentialsNotFound,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsFindVCsFailReason {
    #[serde(rename = "type")]
    pub type_: JsFindVCsFailReasonType,
    pub paths: Option<Vec<Vec<String>>>,
}

impl TryFrom<FindVCsFailReason> for JsFindVCsFailReason {
    type Error = JsError;

    fn try_from(value: FindVCsFailReason) -> Result<Self, JsError> {
        let result = match value {
            FindVCsFailReason::CredentialsNotFound => JsFindVCsFailReason {
                type_: JsFindVCsFailReasonType::CredentialsNotFound,
                paths: None,
            },
            FindVCsFailReason::TypesNotMatched => JsFindVCsFailReason {
                type_: JsFindVCsFailReasonType::TypesNotMatched,
                paths: None,
            },
            FindVCsFailReason::Paths(claim_paths) => JsFindVCsFailReason {
                type_: JsFindVCsFailReasonType::Paths,
                paths: Some(claim_paths),
            },
        };
        Ok(result)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsFindResult {
    data: Value,
}

impl TryFrom<ASDKCredentialsSearchResult> for CredentialsFindResult {
    type Error = JsError;

    fn try_from(value: ASDKCredentialsSearchResult) -> Result<Self, Self::Error> {
        let data = match value {
            ASDKCredentialsSearchResult::Credentials(creds) => {
                let mut result = vec![];
                for cred in creds {
                    let item: JsCredentialEntry = cred.try_into()?;
                    result.push(item);
                }
                serde_json::to_value(result)?
            }
            ASDKCredentialsSearchResult::Reason(reason) => {
                let js_reason: JsFindVCsFailReason = reason.try_into()?;
                serde_json::to_value(js_reason)?
            }
        };

        Ok(CredentialsFindResult { data })
    }
}
