use crate::vc::JsCredential;
use agent_sdk::vc::oid4vci::{CredentialResponseResolved, CredentialResult};
use js_sys::JSON;
use serde_json::json;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsError};

mod builder;
mod credential_offer_resolver;
mod holder;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "OID4VCIIssuerMetadata")]
    pub type OID4VCIIssuerMetadata;

    #[wasm_bindgen(typescript_type = "TokenResponse")]
    pub type TokenResponse;

    #[wasm_bindgen(typescript_type = "OID4VCICredentialOffer")]
    pub type OID4VCICredentialOffer;

    #[wasm_bindgen(typescript_type = "CredentialResponse")]
    pub type CredentialResponse;
}

impl TryFrom<CredentialResponseResolved> for CredentialResponse {
    type Error = JsError;

    fn try_from(value: CredentialResponseResolved) -> Result<Self, Self::Error> {
        let nonce_data = serde_json::to_value(&value.nonce_data)?;

        let mut json_value = match value.data {
            CredentialResult::Deferred { transaction_id } => {
                json!({
                    "data": {
                        "transaction_id": transaction_id,
                    }
                })
            }
            CredentialResult::Credential {
                credential,
                notification_id,
            } => {
                let js_credential: JsCredential = credential.try_into()?;

                json!({
                    "data": {
                        "credential": js_credential,
                        "notification_id": notification_id,
                    }
                })
            }
        };

        json_value["nonceData"] = nonce_data;

        let json_str = serde_json::to_string(&json_value)?;

        JSON::parse(&json_str)
            .map(|value| value.unchecked_into())
            .map_err(|js_value| JsError::new(&format!("JSON parse error: {:?}", js_value)))
    }
}
