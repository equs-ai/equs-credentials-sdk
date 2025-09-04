use agent_sdk::vc::oid4vp::ResolvedAuthRequest;
use std::collections::HashMap;

use crate::common::Result;
use crate::common::{Duration, Error, JsonValue};
use crate::crypto::KeyMetadata;
use crate::utils::parse_url_arg;

mod builder;
pub mod holder;

pub type CoreTransactionDataItem = agent_sdk::vc::oid4vp::TransactionDataItem;
pub type IdTokenMetadata = agent_sdk::vc::oid4vp::IdTokenMetadata;
pub type AuthorizationResponseMetadata = agent_sdk::vc::oid4vp::AuthorizationResponseMetadata;

#[uniffi::remote(Record)]
pub struct IdTokenMetadata {
    pub key_metadata: KeyMetadata,
    pub lifetime: Duration,
}

#[uniffi::remote(Record)]
pub struct AuthorizationResponseMetadata {
    pub claims_to_exclude: Option<HashMap<String, Vec<String>>>,
    pub id_token_metadata: Option<IdTokenMetadata>,
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
    pub response_uri: String,
    pub state: Option<String>,
    pub transaction_data: Option<Vec<TransactionDataItem>>,
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
        Ok(ResolvedAuthRequest {
            client_id: value.client_id,
            client_metadata: serde_json::from_value(value.client_metadata)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            resolved_presentation_query: serde_json::from_value(value.presentation_definition)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            nonce: serde_json::from_value(serde_json::Value::String(value.nonce))
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: parse_url_arg(&value.response_uri)
                .map_err(|e| Error::OID4VPHolder(e.to_string()))?,
            state: value.state,
            transaction_data,
        })
    }
}

impl TryFrom<ResolvedAuthRequest> for AuthorizationRequest {
    type Error = Error;

    fn try_from(value: ResolvedAuthRequest) -> Result<Self> {
        Ok(AuthorizationRequest {
            client_id: value.client_id,
            client_metadata: serde_json::to_value(&value.client_metadata)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            presentation_definition: serde_json::to_value(&value.resolved_presentation_query)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            nonce: value.nonce.secret().to_string(),
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: value.response_uri.to_string(),
            state: value.state,
            transaction_data: value.transaction_data.map(|items| {
                items
                    .iter()
                    .map(|v| v.to_owned().into())
                    .collect::<Vec<_>>()
            }),
        })
    }
}
