use crate::utils::from_json_object;
use crate::vc::JsonObject;
use agent_sdk::vc::oid4vp::{
    AuthorizationResponse, AuthorizationResponseObject, HashAlgorithm, PresentationResult,
    TransactionDataHashes, TransactionDataHashesAlg, TransactionDataResponse,
};
use agent_sdk::vc::presentation_exchange::PresentationSubmission;
use napi::Error;
use napi_derive::napi;

pub mod builder;
pub mod error;
pub mod holder;
pub mod verifier;

#[napi(js_name = "InnerPresentationResult", object)]
pub struct JsPresentationResult {
    pub type_: PresentationResultType,
    pub value: Option<serde_json::Value>,
}

#[napi(string_enum)]
pub enum PresentationResultType {
    AuthorizationResponse,
    RedirectUri,
    Presented,
}

/// An OID4VP authorization response.
/// It can be either plain object as below or the Jwe response string of the fields below
/// @property {any} vpToken - VP Token containing the Verifiable Presentation(s).
/// @property {string | null} [idToken] - The OpenID Connect ID token used in the SIOP flow.
/// @property {PresentationSubmission} presentationSubmission - Details of the submitted presentation.
/// @property {string | null} [state] - The state may be used by a verifier to link requests and responses.
#[napi(js_name = "AuthorizationResponseType")]
pub enum JsAuthorizationResponseType {
    Plain,
    Jwe,
}

#[napi(js_name = "InnerAuthorizationResponse", object)]
pub struct JsInnerAuthorizationResponse {
    pub type_: JsAuthorizationResponseType,
    pub object: Option<JsAuthorizationResponseObject>,
    pub jwe: Option<String>,
}

impl TryFrom<JsInnerAuthorizationResponse> for AuthorizationResponse {
    type Error = Error;

    fn try_from(value: JsInnerAuthorizationResponse) -> napi::Result<Self> {
        match value.type_ {
            JsAuthorizationResponseType::Plain => {
                let object = value.object.ok_or(Error::from_reason(
                    "AuthorizationResponseObject was expected but none",
                ))?;
                Ok(AuthorizationResponse::Plain(object.try_into()?))
            }
            JsAuthorizationResponseType::Jwe => {
                let jwe = value.jwe.ok_or(Error::from_reason(
                    "AuthorizationResponse Jwe was expected but none",
                ))?;
                Ok(AuthorizationResponse::Jwe(jwe))
            }
        }
    }
}

/// An OID4VP authorization response object.
///
/// @property {any} vpToken - VP Token containing the Verifiable Presentation(s).
/// @property {string | null} [idToken] - The OpenID Connect ID token used in the SIOP flow.
/// @property {PresentationSubmission} presentationSubmission - Details of the submitted presentation.
/// @property {string | null} [state] - The state may be used by a verifier to link requests and responses.
#[napi(js_name = "AuthorizationResponseObject", object)]
pub struct JsAuthorizationResponseObject {
    pub vp_token: serde_json::Value,
    pub id_token: Option<String>,
    #[napi(ts_type = "PresentationSubmission")]
    pub presentation_submission: Option<JsonObject>,
    pub state: Option<String>,
    pub transaction_data_response: Option<JsTransactionDataResponse>,
}

#[derive(Clone)]
#[napi(js_name = "TransactionDataResponse", object)]
pub struct JsTransactionDataResponse {
    pub hashes: Vec<String>,
    pub alg: Option<String>,
}

impl TryFrom<JsTransactionDataResponse> for TransactionDataResponse {
    type Error = Error;
    fn try_from(value: JsTransactionDataResponse) -> napi::Result<Self> {
        let transaction_data_hashes = TransactionDataHashes(value.hashes);
        let transaction_data_hashes_alg = match value.alg {
            None => None,
            Some(a) => {
                let hash_alg: HashAlgorithm = a
                    .try_into()
                    .map_err(|_| Error::from_reason("Unsupported Hash algorithm".to_string()))?;
                Some(TransactionDataHashesAlg(hash_alg))
            }
        };
        Ok(Self {
            transaction_data_hashes,
            transaction_data_hashes_alg,
        })
    }
}

impl TryFrom<JsAuthorizationResponseObject> for AuthorizationResponseObject {
    type Error = Error;

    fn try_from(value: JsAuthorizationResponseObject) -> napi::Result<Self> {
        let ps: Option<PresentationSubmission> = value
            .presentation_submission
            .map(from_json_object)
            .transpose()?;
        let transaction_data_response = match value.transaction_data_response {
            None => None,
            Some(tdr) => {
                let t = tdr.try_into()?;
                Some(t)
            }
        };
        Ok(Self {
            vp_token: value.vp_token,
            id_token: value.id_token,
            presentation_submission: ps,
            state: value.state,
            transaction_data_response,
        })
    }
}

impl TryFrom<PresentationResult> for JsPresentationResult {
    type Error = Error;

    fn try_from(value: PresentationResult) -> napi::Result<Self> {
        let result = match value {
            PresentationResult::AuthorizationResponse(auth_resp) => JsPresentationResult {
                type_: PresentationResultType::AuthorizationResponse,
                value: Some(serde_json::to_value(&auth_resp)?),
            },
            PresentationResult::RedirectUri(uri) => JsPresentationResult {
                type_: PresentationResultType::RedirectUri,
                value: Some(serde_json::to_value(&uri)?),
            },
            PresentationResult::Presented => JsPresentationResult {
                type_: PresentationResultType::Presented,
                value: None,
            },
        };

        Ok(result)
    }
}
