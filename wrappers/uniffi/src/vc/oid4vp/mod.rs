use crate::common::Result;
use crate::common::{Duration, Error, JsonValue};
use crate::crypto::KeyMetadata;
use crate::utils::parse_url_arg;
use agent_sdk::vc::oid4vp::{
    AuthorizationResponse as AsdkAuthorizationResponse,
    AuthorizationResponseObject as AsdkAuthorizationResponseObject,
    PresentationResult as AsdkPresentationResult,
};
use agent_sdk::vc::oid4vp::{ClientId, ResolvedAuthRequest};
use std::collections::HashMap;
mod builder;
pub mod holder;

pub type CoreTransactionDataItem = agent_sdk::vc::oid4vp::TransactionDataItem;
pub type IdTokenMetadata = agent_sdk::vc::oid4vp::IdTokenMetadata;
pub type AuthorizationResponseMetadata = agent_sdk::vc::oid4vp::AuthorizationResponseMetadata;

#[derive(uniffi::Enum)]
#[allow(clippy::large_enum_variant)]
pub enum AuthorizationResponse {
    Plain(AuthorizationResponseObject),
    Jwe(String),
}

#[derive(uniffi::Record)]
pub struct AuthorizationResponseObject {
    pub vp_token: JsonValue,
    pub presentation_submission: Option<JsonValue>,
    pub id_token: Option<String>,
    pub state: Option<String>,
    pub transaction_data_hashes: Option<Vec<String>>,
    pub transaction_data_hashes_alg: Option<String>,
}

#[derive(uniffi::Enum)]
#[allow(clippy::large_enum_variant)]
pub enum PresentationResult {
    AuthResponse(AuthorizationResponse),
    RedirectUri(String),
    Presented,
}

#[uniffi::remote(Record)]
pub struct IdTokenMetadata {
    pub key_metadata: KeyMetadata,
    pub lifetime: Duration,
}

#[uniffi::remote(Record)]
pub struct AuthorizationResponseMetadata {
    pub claims_to_exclude: Option<HashMap<String, Vec<String>>>,
    pub id_token_metadata: Option<IdTokenMetadata>,
    pub dc_api_origin: Option<String>,
}

#[derive(uniffi::Record)]
pub struct TransactionDataItem {
    pub type_: String,
    pub credential_ids: Vec<String>,
    pub transaction_data_hashes_alg: Option<Vec<String>>,
}

impl TryFrom<TransactionDataItem> for CoreTransactionDataItem {
    type Error = Error;

    fn try_from(value: TransactionDataItem) -> Result<Self> {
        let transaction_data_hashes_alg = if let Some(algs) = value.transaction_data_hashes_alg {
            let mut items = Vec::new();
            for alg in algs {
                items.push(
                    alg.try_into()
                        .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
                );
            }
            Some(items)
        } else {
            None
        };
        Ok(Self {
            type_: value.type_,
            credential_ids: value.credential_ids,
            transaction_data_hashes_alg,
        })
    }
}

impl From<CoreTransactionDataItem> for TransactionDataItem {
    fn from(value: CoreTransactionDataItem) -> Self {
        Self {
            type_: value.type_,
            credential_ids: value.credential_ids,
            transaction_data_hashes_alg: value
                .transaction_data_hashes_alg
                .map(|algs| algs.iter().map(|v| v.to_string()).collect::<Vec<_>>()),
        }
    }
}

#[derive(uniffi::Record)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub client_metadata: JsonValue,
    pub presentation_definition: JsonValue,
    pub nonce: String,
    pub response_type: String,
    pub response_mode: String,
    pub response_uri: Option<String>,
    pub state: Option<String>,
    pub transaction_data: Option<Vec<TransactionDataItem>>,
    pub expected_origins: Option<Vec<String>>,
}

impl TryFrom<AuthorizationRequest> for ResolvedAuthRequest {
    type Error = Error;

    fn try_from(value: AuthorizationRequest) -> Result<Self> {
        let transaction_data = if let Some(items) = value.transaction_data {
            let mut td_items = Vec::new();
            for item in items {
                td_items.push(item.try_into()?);
            }
            Some(td_items)
        } else {
            None
        };

        let client_id = ClientId::new(value.client_id).map_err(|e| {
            Error::OID4VPHolder(format!(
                "Error while converting into client id: {} It should have format: <scheme>:<id>.",
                e
            ))
        })?;
        Ok(ResolvedAuthRequest {
            client_id,
            client_metadata: serde_json::from_value(value.client_metadata)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            resolved_presentation_query: serde_json::from_value(value.presentation_definition)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            nonce: serde_json::from_value(serde_json::Value::String(value.nonce))
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: value
                .response_uri
                .map(|uri| parse_url_arg(&uri).map_err(|e| Error::OID4VPHolder(e.to_string())))
                .transpose()?,
            state: value.state,
            transaction_data,
            expected_origins: value.expected_origins,
        })
    }
}

impl TryFrom<ResolvedAuthRequest> for AuthorizationRequest {
    type Error = Error;

    fn try_from(value: ResolvedAuthRequest) -> Result<Self> {
        Ok(AuthorizationRequest {
            client_id: value.client_id.get_full_id(),
            client_metadata: serde_json::to_value(&value.client_metadata)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            presentation_definition: serde_json::to_value(&value.resolved_presentation_query)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            nonce: value.nonce.secret().to_string(),
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: value.response_uri.map(|uri| uri.to_string()),
            state: value.state,
            transaction_data: value.transaction_data.map(|items| {
                items
                    .iter()
                    .map(|v| v.to_owned().into())
                    .collect::<Vec<_>>()
            }),
            expected_origins: value.expected_origins,
        })
    }
}

impl From<AsdkPresentationResult> for PresentationResult {
    fn from(value: AsdkPresentationResult) -> Self {
        match value {
            AsdkPresentationResult::AuthorizationResponse(auth_response) => match auth_response {
                AsdkAuthorizationResponse::Plain(auth_response) => {
                    PresentationResult::AuthResponse(AuthorizationResponse::Plain(
                        auth_response.into(),
                    ))
                }
                AsdkAuthorizationResponse::Jwe(jwe) => {
                    PresentationResult::AuthResponse(AuthorizationResponse::Jwe(jwe))
                }
            },
            AsdkPresentationResult::RedirectUri(uri) => {
                PresentationResult::RedirectUri(uri.to_string())
            }
            AsdkPresentationResult::Presented => PresentationResult::Presented,
        }
    }
}

impl From<AsdkAuthorizationResponseObject> for AuthorizationResponseObject {
    fn from(value: AsdkAuthorizationResponseObject) -> Self {
        let (transaction_data_hashes, transaction_data_hashes_alg) = value
            .transaction_data_response
            .map(|t| {
                (
                    Some(t.transaction_data_hashes.0),
                    t.transaction_data_hashes_alg
                        .map(|v| JsonValue::from(v).to_string()),
                )
            })
            .unwrap_or((None, None));

        AuthorizationResponseObject {
            vp_token: value.vp_token,
            presentation_submission: value.presentation_submission.map(|v| v.into()),
            id_token: value.id_token,
            state: value.state,
            transaction_data_hashes,
            transaction_data_hashes_alg,
        }
    }
}
