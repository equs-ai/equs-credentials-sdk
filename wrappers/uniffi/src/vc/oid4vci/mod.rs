use crate::common::JsonValue;
use crate::vc::Credential;
use agent_sdk::vc::core::{
    DEFAULT_POP_LIFETIME_MINUTES, ProofOfPossessionMetadata,
    ProofOfPossessionNotBefore as ASDKPoPNotBefore,
};
use agent_sdk::vc::oid4vci::CredentialExtraVerification as ASDKCredentialExtraVerification;
use oauth2::helpers::{deserialize_space_delimited_vec, serialize_space_delimited_vec};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uniffi::custom_type;

mod builder;
mod credential_offer_resolver;
pub mod holder;
mod metadata;

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

#[derive(uniffi::Enum)]
pub enum ProofOfPossessionNotBefore {
    /// Sets nbf the same as iat.
    AsIssuedAt,
    /// Sets nbf to provided timestamp.
    Fixed(OffsetDateTime),
    /// Sets nbf with a given delay from iat.
    ///
    /// Example:
    ///     `iat` is 10:00:00;
    ///     `delay` is 5 min;
    ///     then `nbf` will be 10:05:00.
    Delay(Duration),
    /// Sets nbf with a given leeway from iat.
    ///
    /// Example:
    ///     `iat` is 10:00:00
    ///     `leeway` is 5 min
    ///     then `nbf` will be 9:55:00
    Leeway(Duration),
}

custom_type!(ASDKPoPNotBefore, ProofOfPossessionNotBefore, {
        remote,
    lower: |nbf| match nbf {

    ASDKPoPNotBefore::AsIssuedAt => ProofOfPossessionNotBefore::AsIssuedAt,
        ASDKPoPNotBefore::Fixed(value) => ProofOfPossessionNotBefore::Fixed(value),
        ASDKPoPNotBefore::Delay(value) => ProofOfPossessionNotBefore::Delay(value),
        ASDKPoPNotBefore::Leeway(value) => ProofOfPossessionNotBefore::Leeway(value)
    },
    try_lift: |nbf| match nbf {

    ProofOfPossessionNotBefore::AsIssuedAt => Ok(ASDKPoPNotBefore::AsIssuedAt),
        ProofOfPossessionNotBefore::Fixed(value) => Ok(ASDKPoPNotBefore::Fixed(value)),
        ProofOfPossessionNotBefore::Delay(value) => Ok(ASDKPoPNotBefore::Delay(value)),
        ProofOfPossessionNotBefore::Leeway(value) => Ok(ASDKPoPNotBefore::Leeway(value))
    },
});

/// A metadata for the `ProofOfPossessionMetadata`.
///
/// Encapsulates all necessary data needed to generate a proof of possession.
#[uniffi::remote(Record)]
pub struct ProofOfPossessionMetadata {
    lifetime: Duration,
    not_before: Option<ASDKPoPNotBefore>,
}

#[derive(uniffi::Object)]
pub struct ProofOfPossessionMetadataBuilder {
    lifetime: Option<Duration>,
    not_before: Option<ASDKPoPNotBefore>,
}

#[uniffi::export()]
impl ProofOfPossessionMetadataBuilder {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            lifetime: None,
            not_before: None,
        }
    }

    pub fn with_lifetime(&self, lifetime: Duration) -> Self {
        Self {
            lifetime: Some(lifetime),
            not_before: self.not_before,
        }
    }
    pub fn with_not_before(&self, not_before: ASDKPoPNotBefore) -> Self {
        Self {
            lifetime: self.lifetime,
            not_before: Some(not_before),
        }
    }

    pub fn build(&self) -> ProofOfPossessionMetadata {
        ProofOfPossessionMetadata {
            not_before: self.not_before,
            lifetime: self
                .lifetime
                .unwrap_or(Duration::minutes(DEFAULT_POP_LIFETIME_MINUTES)),
        }
    }
}

#[derive(uniffi::Enum)]
pub enum CredentialExtraVerification {
    CredentialIssuerIdentifier,
}

custom_type!(ASDKCredentialExtraVerification, CredentialExtraVerification, {
        remote,
    lower: |cev| match cev {
        ASDKCredentialExtraVerification::CredentialIssuerIdentifier => CredentialExtraVerification::CredentialIssuerIdentifier
    },
    try_lift: |cev| match cev {
        CredentialExtraVerification::CredentialIssuerIdentifier => Ok(ASDKCredentialExtraVerification::CredentialIssuerIdentifier)
    },
});
