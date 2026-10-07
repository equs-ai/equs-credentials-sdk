use crate::common::Result;
use crate::common::{Duration, Error, JsonValue};
use crate::crypto::KeyMetadata;
use crate::utils::parse_url_arg;
use equs_sdk::vc::oid4vp::{
    AuthorizationResponse as EqusSdkAuthorizationResponse,
    AuthorizationResponseObject as EqusSdkAuthorizationResponseObject,
    PresentationResult as EqusSdkPresentationResult,
};
use equs_sdk::vc::oid4vp::{ClientId, ResolvedAuthRequest, TRANSACTION_TYPE_DELEGATE, as_delegate};
use std::collections::HashMap;
mod builder;
pub mod holder;

pub type CoreTransactionDataItem = equs_sdk::vc::oid4vp::TransactionDataItem;
pub type IdTokenMetadata = equs_sdk::vc::oid4vp::IdTokenMetadata;
pub type AuthorizationResponseMetadata = equs_sdk::vc::oid4vp::AuthorizationResponseMetadata;

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

/// Keys of a transaction-data item that the record carries in its own fields.
const TRANSACTION_DATA_ITEM_KEYS: [&str; 3] =
    ["type", "credential_ids", "transaction_data_hashes_alg"];

#[derive(uniffi::Record)]
pub struct TransactionDataItem {
    pub type_: String,
    pub credential_ids: Vec<String>,
    pub transaction_data_hashes_alg: Option<Vec<String>>,
    /// Every other field of the item as a JSON object, e.g. `format` and
    /// `delegate_payload_disclosure` for a `delegate` item; `None` when there are none.
    #[uniffi(default = None)]
    pub data: Option<JsonValue>,
}

impl TryFrom<TransactionDataItem> for CoreTransactionDataItem {
    type Error = Error;

    fn try_from(value: TransactionDataItem) -> Result<Self> {
        let mut item = match value.data {
            None => serde_json::Map::new(),
            Some(serde_json::Value::Object(data)) => data,
            Some(_) => {
                return Err(Error::OID4VPHolder(
                    "transaction data item `data` must be a JSON object".to_string(),
                ));
            }
        };
        if let Some(key) = TRANSACTION_DATA_ITEM_KEYS
            .into_iter()
            .find(|key| item.contains_key(*key))
        {
            return Err(Error::OID4VPHolder(format!(
                "transaction data item `data` must not contain `{key}`"
            )));
        }
        item.insert("type".to_string(), value.type_.into());
        item.insert("credential_ids".to_string(), value.credential_ids.into());
        if let Some(algs) = value.transaction_data_hashes_alg {
            item.insert("transaction_data_hashes_alg".to_string(), algs.into());
        }
        let item: CoreTransactionDataItem = serde_json::from_value(serde_json::Value::Object(item))
            .map_err(|e| Error::OID4VPHolder(format!("invalid transaction data item: {e}")))?;
        // A malformed `delegate` item parses as `Unknown` rather than failing.
        if item.type_() == TRANSACTION_TYPE_DELEGATE && as_delegate(&item).is_none() {
            return Err(Error::OID4VPHolder(
                "invalid `delegate` transaction data item".to_string(),
            ));
        }
        Ok(item)
    }
}

impl TryFrom<CoreTransactionDataItem> for TransactionDataItem {
    type Error = Error;

    fn try_from(value: CoreTransactionDataItem) -> Result<Self> {
        let type_ = value.type_().to_owned();
        let serde_json::Value::Object(mut data) = serde_json::to_value(&value.content)
            .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?
        else {
            return Err(Error::OID4VPHolder(
                "transaction data item content must be a JSON object".to_string(),
            ));
        };
        data.remove("type");
        Ok(Self {
            type_,
            credential_ids: value.credential_ids,
            transaction_data_hashes_alg: value
                .transaction_data_hashes_alg
                .map(|algs| algs.iter().map(|v| v.to_string()).collect::<Vec<_>>()),
            data: (!data.is_empty()).then_some(serde_json::Value::Object(data)),
        })
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
            transaction_data: value
                .transaction_data
                .map(|items| {
                    items
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?,
            expected_origins: value.expected_origins,
        })
    }
}

impl From<EqusSdkPresentationResult> for PresentationResult {
    fn from(value: EqusSdkPresentationResult) -> Self {
        match value {
            EqusSdkPresentationResult::AuthorizationResponse(auth_response) => {
                match auth_response {
                    EqusSdkAuthorizationResponse::Plain(auth_response) => {
                        PresentationResult::AuthResponse(AuthorizationResponse::Plain(
                            auth_response.into(),
                        ))
                    }
                    EqusSdkAuthorizationResponse::Jwe(jwe) => {
                        PresentationResult::AuthResponse(AuthorizationResponse::Jwe(jwe))
                    }
                }
            }
            EqusSdkPresentationResult::RedirectUri(uri) => {
                PresentationResult::RedirectUri(uri.to_string())
            }
            EqusSdkPresentationResult::Presented => PresentationResult::Presented,
        }
    }
}

impl From<EqusSdkAuthorizationResponseObject> for AuthorizationResponseObject {
    fn from(value: EqusSdkAuthorizationResponseObject) -> Self {
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
