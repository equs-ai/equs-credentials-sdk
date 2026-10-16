use equs_sdk::vc::VCFormat;
use equs_sdk::vc::oid4vp::{
    CredentialsFindResult as EqusSdkCredentialsSearchResult, FindVCsFailReason,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

pub mod core;
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

    #[wasm_bindgen(typescript_type = "CredentialOffer")]
    pub type CredentialOffer;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsCredential {
    format: VCFormat,
    payload: String,
}

impl TryFrom<equs_sdk::vc::Credential> for JsCredential {
    type Error = JsError;
    fn try_from(value: equs_sdk::vc::Credential) -> Result<Self, JsError> {
        let js_credential = match value {
            equs_sdk::vc::Credential::SdJwt(payload) => JsCredential {
                format: VCFormat::SdJwtVc,
                payload,
            },
            equs_sdk::vc::Credential::LdpVc(payload) => JsCredential {
                format: VCFormat::LdpVc,
                payload: serde_json::to_string(&payload)?,
            },
            equs_sdk::vc::Credential::JwtVcJson(payload) => JsCredential {
                format: VCFormat::JwtVcJson,
                payload,
            },
            equs_sdk::vc::Credential::JwtVcJsonLd(payload) => JsCredential {
                format: VCFormat::JwtVcJsonLD,
                payload,
            },
            _ => Err(JsError::new("Unsupported VC format"))?,
        };

        Ok(js_credential)
    }
}

impl TryFrom<JsCredential> for equs_sdk::vc::Credential {
    type Error = JsError;

    fn try_from(value: JsCredential) -> Result<Self, JsError> {
        match value.format {
            VCFormat::JwtVcJson => Ok(equs_sdk::vc::Credential::JwtVcJson(value.payload)),
            VCFormat::JwtVcJsonLD => Ok(equs_sdk::vc::Credential::JwtVcJsonLd(value.payload)),
            VCFormat::LdpVc => Ok(equs_sdk::vc::Credential::LdpVc(serde_json::from_str(
                &value.payload,
            )?)),
            VCFormat::SdJwtVc => Ok(equs_sdk::vc::Credential::SdJwt(value.payload)),
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

impl TryFrom<equs_sdk::vault::CredentialEntry> for JsCredentialEntry {
    type Error = JsError;

    fn try_from(value: equs_sdk::vault::CredentialEntry) -> Result<Self, JsError> {
        Ok(JsCredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

impl TryFrom<JsCredentialEntry> for equs_sdk::vault::CredentialEntry {
    type Error = JsError;

    fn try_from(value: JsCredentialEntry) -> Result<Self, JsError> {
        Ok(equs_sdk::vault::CredentialEntry {
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
#[serde(untagged)]
enum CredentialsFindResultData {
    Credentials(Vec<JsCredentialEntry>),
    Reason(JsFindVCsFailReason),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsFindResult {
    data: CredentialsFindResultData,
}

impl TryFrom<EqusSdkCredentialsSearchResult> for CredentialsFindResult {
    type Error = JsError;

    fn try_from(value: EqusSdkCredentialsSearchResult) -> Result<Self, Self::Error> {
        let data = match value {
            EqusSdkCredentialsSearchResult::Credentials(creds) => {
                let result = creds
                    .into_iter()
                    .map(JsCredentialEntry::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                CredentialsFindResultData::Credentials(result)
            }
            EqusSdkCredentialsSearchResult::Reason(reason) => {
                CredentialsFindResultData::Reason(reason.try_into()?)
            }
        };

        Ok(CredentialsFindResult { data })
    }
}
