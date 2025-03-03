use agent_sdk::vc::VCFormat;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

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
