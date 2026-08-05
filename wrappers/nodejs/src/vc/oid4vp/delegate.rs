use crate::error::IntoNapiError;
use crate::nonce::JsNonceHandler;
use crate::utils::{from_json_object, to_json_object};
use crate::vc::JsonObject;
use agent_sdk::vc::oid4vp::{DelegationRequest, delegate_transaction_data_item};
use napi::{Error, Result};
use napi_derive::napi;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "format")]
enum JsDelegationRequest {
    #[serde(rename = "dSD-JWT")]
    Open {
        #[serde(rename = "credentialIds")]
        credential_ids: Vec<String>,
        #[serde(rename = "payloadClaims", default)]
        payload_claims: Option<JsonObject>,
    },
    #[serde(rename = "dSD-JWT+KB")]
    HolderBinding {
        #[serde(rename = "credentialIds")]
        credential_ids: Vec<String>,
        #[serde(rename = "delegateJwk")]
        delegate_jwk: JsonObject,
        #[serde(rename = "payloadClaims", default)]
        payload_claims: Option<JsonObject>,
    },
}

impl TryFrom<JsDelegationRequest> for DelegationRequest {
    type Error = Error;

    fn try_from(value: JsDelegationRequest) -> Result<Self> {
        match value {
            JsDelegationRequest::Open {
                credential_ids,
                payload_claims,
            } => DelegationRequest::open(credential_ids, payload_claims.unwrap_or_default())
                .map_err(IntoNapiError::into_napi_error),
            JsDelegationRequest::HolderBinding {
                credential_ids,
                delegate_jwk: delegate_cnf,
                payload_claims,
            } => DelegationRequest::holder_binding(
                credential_ids,
                from_json_object(delegate_cnf)?,
                payload_claims.unwrap_or_default(),
            )
            .map_err(IntoNapiError::into_napi_error),
        }
    }
}

/// Builds a `delegate` Transaction Data item for an Authorization Request.
///
/// Generates the disclosure salt via `nonceHandler`, assembles the Array Disclosure
/// `base64url([salt, { cnf?, ...payloadClaims }])` and wraps it in a transaction-data item
/// ready to pass as an element of {@link AuthorizationRequestMetadata}.transactionData.
///
/// Salt generation and disclosure encoding are security-sensitive;
///
/// @param {DelegationRequest} request - What to ask the Holder to delegate.
/// @param {NonceHandler} nonceHandler - Used to generate the disclosure salt. A plain object
///   (`{ generate, validate }`) works as-is; a **class instance** must be wrapped with
///   `contextEnsuredNonceHandler(handler)` first, because the native side calls `generate`
///   without a receiver and an unbound prototype method aborts the process.
///
/// @returns {TransactionDataItem} - The `delegate` transaction-data item.
/// @throws {Error} If `request` does not match the `DelegationRequest` shape, or if
///   `payloadClaims` contains `cnf` or `_sd`.
#[napi(ts_return_type = "Promise<TransactionDataItem>")]
pub async fn build_delegate_transaction_data(
    #[napi(ts_arg_type = "DelegationRequest")] request: JsonObject,
    nonce_handler: JsNonceHandler,
) -> Result<JsonObject> {
    let request: JsDelegationRequest = from_json_object(request)?;
    let request: DelegationRequest = request.try_into()?;
    let item = delegate_transaction_data_item(&request, &nonce_handler)
        .await
        .map_err(IntoNapiError::into_napi_error)?;
    to_json_object(item)
}
