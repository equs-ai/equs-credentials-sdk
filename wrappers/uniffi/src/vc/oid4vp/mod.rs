use crate::common::Result;
use crate::common::{Duration, Error, JsonMap, JsonValue};
use crate::crypto::KeyMetadata;
use crate::utils::parse_url_arg;
use equs_sdk::vc::oid4vp::{
    AuthorizationResponse as EqusSdkAuthorizationResponse,
    AuthorizationResponseObject as EqusSdkAuthorizationResponseObject,
    PresentationResult as EqusSdkPresentationResult,
};
use equs_sdk::vc::oid4vp::{
    ClientId, FORMAT_DSD_JWT, FORMAT_DSD_JWT_KB, ResolvedAuthRequest, TRANSACTION_TYPE_DELEGATE,
};
pub use equs_sdk::vc::oid4vp::{
    DelegateSdJwtTransactionData, DelegateSdJwtTransactionDataFormat, HashAlgorithm,
    TransactionDataItem, TransactionDataItemTypeContent,
};
use std::collections::HashMap;
mod builder;
pub mod holder;

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

/// A transaction-data item of an authorization request, as the SDK holds it.
#[uniffi::remote(Record)]
pub struct TransactionDataItem {
    pub credential_ids: Vec<String>,
    pub transaction_data_hashes_alg: Option<Vec<HashAlgorithm>>,
    pub content: TransactionDataItemTypeContent,
}

/// The type-specific part of a [`TransactionDataItem`].
#[uniffi::remote(Enum)]
pub enum TransactionDataItemTypeContent {
    /// A `delegate` item.
    DelegateSdJwt(DelegateSdJwtTransactionData),
    /// Any other type, with its fields as a JSON object; also a malformed `delegate` item.
    Unknown { type_: String, data: JsonMap },
}

/// A `delegate` item (dSD-JWT draft section 7.1).
#[uniffi::remote(Record)]
pub struct DelegateSdJwtTransactionData {
    pub format: DelegateSdJwtTransactionDataFormat,
    /// base64url of `[salt, {cnf?, ...claims}]`.
    pub delegate_payload_disclosure: String,
    pub delegate_disclosures: Option<Vec<String>>,
}

#[uniffi::remote(Enum)]
pub enum DelegateSdJwtTransactionDataFormat {
    /// `dSD-JWT`
    Open,
    /// `dSD-JWT+KB`
    HolderBinding,
}

#[uniffi::remote(Enum)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Rejects `delegate` items unless the holder allows delegation, and any malformed one, which
/// the SDK would answer with an ordinary presentation.
pub(crate) fn check_delegate_items(
    request: &ResolvedAuthRequest,
    allow_delegation: bool,
) -> Result<()> {
    let delegate_items: Vec<&TransactionDataItem> = request
        .transaction_data
        .iter()
        .flatten()
        .filter(|item| item.type_() == TRANSACTION_TYPE_DELEGATE)
        .collect();
    if delegate_items.is_empty() {
        return Ok(());
    }
    if !allow_delegation {
        return Err(Error::OID4VPHolder(
            "the request asks for a delegation, but delegation is not enabled for this holder"
                .to_string(),
        ));
    }
    for item in delegate_items {
        if let TransactionDataItemTypeContent::Unknown { data, .. } = &item.content {
            return Err(Error::OID4VPHolder(format!(
                "`delegate` transaction data item {}",
                unparsed_delegate_reason(data)
            )));
        }
    }
    Ok(())
}

/// Why a `delegate` item did not parse as one; names the field without quoting its value.
fn unparsed_delegate_reason(data: &JsonMap) -> &'static str {
    let format = data.get("format").and_then(serde_json::Value::as_str);
    if !data.contains_key("format") {
        "has no `format`"
    } else if !matches!(format, Some(FORMAT_DSD_JWT | FORMAT_DSD_JWT_KB)) {
        "has an unsupported `format`"
    } else if !data.contains_key("delegate_payload_disclosure") {
        "has no `delegate_payload_disclosure`"
    } else {
        "does not parse"
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
            transaction_data: value.transaction_data,
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
            transaction_data: value.transaction_data,
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
