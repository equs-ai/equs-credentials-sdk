use crate::common::JsonValue;
use crate::vc::Credential;
use oauth2::helpers::{deserialize_space_delimited_vec, serialize_space_delimited_vec};
use serde::{Deserialize, Serialize};
use uniffi::custom_type;

mod builder;
mod credential_offer_resolver;
pub mod holder;

pub type CredentialResult = agent_sdk::vc::oid4vci::CredentialResult;
pub type CredentialResponse = agent_sdk::vc::oid4vci::CredentialResponseResolved;
pub type TokenResponse = agent_sdk::vc::oid4vci::TokenResponse;

#[derive(uniffi::Enum)]
pub enum CredentialResultEnum {
    Deferred {
        transaction_id: String,
    },
    Immediate {
        credentials: Vec<Credential>,
        notification_id: Option<String>,
    },
}

custom_type!(CredentialResult, CredentialResultEnum, {
    remote,
    lower: |credential_result| match credential_result {
        CredentialResult::Deferred { transaction_id } =>
            CredentialResultEnum::Deferred { transaction_id },
        CredentialResult::Credential { credentials, notification_id } =>
            CredentialResultEnum::Immediate { credentials, notification_id },
    },
    try_lift: |credential_result| match credential_result {
        CredentialResultEnum::Deferred { transaction_id } =>
            Ok(CredentialResult::Deferred { transaction_id }),
        CredentialResultEnum::Immediate { credentials, notification_id } =>
            Ok(CredentialResult::Credential { credentials, notification_id }),
    },
});

#[uniffi::remote(Record)]
pub struct CredentialResponse {
    pub data: CredentialResult,
}

#[derive(uniffi::Record, Clone, Debug, Deserialize, Serialize)]
pub struct TokenResponseData {
    pub access_token: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "deserialize_space_delimited_vec")]
    #[serde(serialize_with = "serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<JsonValue>,
}

custom_type!(TokenResponse, TokenResponseData, {
    remote,
    lower: |token_response| serde_json::to_value(token_response)
        .and_then(serde_json::from_value)
        .expect("unable serialize TokenResponse"),
    try_lift: |token_reponse_data| Ok(
        serde_json::to_value(token_reponse_data).and_then(serde_json::from_value)?
    ),
});
