use crate::utils;
use crate::utils::convert_to_opaque_object;
use crate::vc::oid4vp::{
    AuthorizationRequest, AuthorizationResponseMetadata, CredentialMapping, CredentialsMapping,
    PresentationResult, VCStatus,
};
use crate::vc::{Credential, CredentialsFindResult, JsCredential, JsCredentialEntry};
use equs_sdk::vault::CredentialEntry;
use equs_sdk::vc::oid4vp::{CredentialsMapping as EqusSdkCredentialsMapping, Holder};
use equs_sdk::vc::status_formats::status_list_token_jwt;
use js_sys::{Object, Reflect};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsError, JsValue};

/// The `OID4VP` `Holder` API.
///
/// Supports presentation flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// # Features
///
/// * Fetch authorization requests from verifiers.
/// * Discovers credentials required for presentation requests.
/// * Supports both automatic and manual credential presentation.
#[wasm_bindgen]
pub struct OID4VPHolder(Box<dyn Holder>);

impl OID4VPHolder {
    pub fn from_holder<H: Holder + 'static>(holder: H) -> OID4VPHolder {
        OID4VPHolder(Box::new(holder))
    }
}

#[wasm_bindgen]
impl OID4VPHolder {
    /// Fetches the `OID4VP` authorization request object from the provided URI.
    /// If the validation of authorization request fails then related `ProtocolError` response will be sent to the `response_uri` endpoint
    ///
    /// # Arguments
    ///
    /// * `request_uri` - a request URI provided by the authorization URL.
    ///
    /// # Returns
    ///
    /// A `ResolvedAuthRequest` with the presentation definition and other relevant details on success.
    ///
    /// # Errors
    ///
    /// * Returns an internal or protocol-specific error.
    #[wasm_bindgen(js_name = getAuthorizationRequest)]
    pub async fn get_authorization_request(
        &self,
        request_uri: String,
    ) -> Result<AuthorizationRequest, JsError> {
        let request_uri = request_uri.parse().map_err(JsError::from)?;

        self.0
            .get_authorization_request(&request_uri)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
            .and_then(utils::convert_to_opaque_object_unchecked)
            .map(|c| AuthorizationRequest::new(&c))
    }

    /// Automatically presents credentials to the Verifier based on the authorization request.
    ///
    /// This method selects the first appropriate credential that matches the requirements of the authorization request.
    /// To present specific credentials, use [OID4VPHolder::find_vcs_for_presentation] to discover suitable credentials and
    /// [OID4VPHolder::present_credentials] to manually present them.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request containing the presentation requirements.
    /// * `metadata` - the metadata for the authorization response.
    ///
    /// # Returns
    ///
    /// * `AuthorizationResponse` - When Digital Credentials API response mode is used (`response_mode: dc_api` or `response_mode: dc_api.jwt`)
    /// * An optional redirect URI which is got either:
    ///     * Optionally can be returned from Verifier after submitting Authorization Response.
    ///     * In the case of Same Device Flow, Authorization Response is embedded into the redirect URI as a fragment.
    ///
    /// # Errors
    ///
    /// * Returns an internal or protocol-specific error.
    #[wasm_bindgen(js_name = presentCredentialsAuto)]
    pub async fn present_credentials_auto(
        &self,
        auth_request: AuthorizationRequest,
        metadata: Option<AuthorizationResponseMetadata>,
    ) -> Result<PresentationResult, JsError> {
        let auth_request = utils::convert_to_rust_object(auth_request.getAuthRequest())?;
        let metadata = metadata
            .map(utils::convert_to_rust_object)
            .transpose()?
            .unwrap_or_else(|| equs_sdk::vc::oid4vp::AuthorizationResponseMetadata::default());

        let js_presentation: JsPresentationResult = self
            .0
            .present_credentials_auto(&auth_request, &metadata)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?
            .try_into()?;

        utils::convert_to_opaque_object_unchecked(js_presentation)
    }

    /// Finds verifiable credentials required for the presentation based on the authorization request.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request containing the presentation requirements.
    ///
    /// # Returns
    ///
    ///  A map of credentials that satisfy the authorization request's requirements.
    ///  If no matching credentials are found, an empty map is returned.
    ///
    /// # Errors
    ///
    /// Returns an internal error
    /// * If there is an issue with parsing the presentation metadata.
    /// * If an error occurs during credential search and extraction
    #[wasm_bindgen(js_name = findVcsForPresentation)]
    pub async fn find_vcs_for_presentation(
        &self,
        auth_request: AuthorizationRequest,
    ) -> Result<CredentialsMapping, JsError> {
        let auth_request = utils::convert_to_rust_object(auth_request.getAuthRequest())?;

        let credentials_mapping = self
            .0
            .find_vcs_for_presentation(&auth_request)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        let map = convert_to_js_credentials_mapping(credentials_mapping)?;
        let js_object = convert_hash_map_of_credentials_to_js_object(map)?;
        Ok(js_object.unchecked_into())
    }

    /// Manually presents credentials to the Verifier.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request.
    /// * `credential_mapping` - the map of credentials required for the presentation.
    /// * `metadata` - the authorization response metadata.
    ///
    /// # Returns
    ///
    /// * `AuthorizationResponse` - When Digital Credentials API response mode is used (`response_mode: dc_api` or `response_mode: dc_api.jwt`)
    /// * An optional redirect URI which is got either:
    ///     * Optionally can be returned from Verifier after submitting Authorization Response.
    ///     * In the case of Same Device Flow, Authorization Response is embedded into the redirect URI as a fragment.
    ///
    /// # Errors
    ///
    /// * Returns an internal or protocol-specific error.
    #[wasm_bindgen(js_name = presentCredentials)]
    pub async fn present_credentials(
        &self,
        auth_request: AuthorizationRequest,
        credential_mapping: CredentialMapping,
        metadata: Option<AuthorizationResponseMetadata>,
    ) -> Result<PresentationResult, JsError> {
        let auth_request = utils::convert_to_rust_object(auth_request.getAuthRequest())?;
        let credential_mapping = utils::convert_to_rust_object(credential_mapping)
            .map_err(|err| JsError::new(&format!("{:?}", err)))
            .and_then(convert_from_js_credential_mapping)?;
        let metadata = metadata
            .map(utils::convert_to_rust_object)
            .transpose()?
            .unwrap_or_else(|| equs_sdk::vc::oid4vp::AuthorizationResponseMetadata::default());

        let js_presentation: JsPresentationResult = self
            .0
            .present_credentials(&auth_request, &credential_mapping, &metadata)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?
            .try_into()?;

        utils::convert_to_opaque_object_unchecked(js_presentation)
    }

    /// Decline the authorization request by sending authorization error response to the `response_uri` endpoint.
    ///
    /// @param {AuthorizationRequest} auth_request - the resolved authorization request.
    ///
    /// @returns {string | null}
    /// An optional redirect URL(in case of Same Device Flow) where the error response is embedded as a fragment.
    #[wasm_bindgen(js_name = declineAuthorizationRequest)]
    pub async fn decline_authorization_request(
        &self,
        auth_request: AuthorizationRequest,
    ) -> Result<Option<String>, JsError> {
        let auth_request = utils::convert_to_rust_object(auth_request.getAuthRequest())?;

        let redirect_url = self
            .0
            .decline_authorization_request(&auth_request)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        Ok(redirect_url.map(|url| url.to_string()))
    }

    /// Gets the status VC.
    ///
    /// # Arguments
    ///
    /// * `credential` - a credential containing the status claim.
    ///
    /// # Returns
    ///
    /// Credential status on success
    ///
    /// # Errors
    ///
    /// Returns an internal error
    /// * If there is an issue with parsing the credential.
    /// * If an error occurs during getting credential status.
    #[wasm_bindgen(js_name = getCredentialStatus)]
    pub async fn get_credential_status(
        &self,
        credential: Credential,
    ) -> Result<Option<VCStatus>, JsError> {
        let js_credential: JsCredential = utils::convert_to_rust_object(credential)?;
        let credential = js_credential.try_into()?;

        let status = self
            .0
            .get_credential_status(&credential)
            .await
            .map(|status| status.map(JsVCStatus::try_from))
            .map_err(|err| JsError::new(&format!("{:?}", err)))?
            .transpose()?;

        status
            .map(|s| {
                utils::convert_to_opaque_object_unchecked(s)
                    .map_err(|err| JsError::new(&format!("{:?}", err)))
            })
            .transpose()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsPresentationResult {
    #[serde(rename = "type")]
    pub type_: PresentationResultType,
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PresentationResultType {
    AuthorizationResponse,
    RedirectUri,
    Presented,
}

impl TryFrom<equs_sdk::vc::oid4vp::PresentationResult> for JsPresentationResult {
    type Error = JsError;

    fn try_from(value: equs_sdk::vc::oid4vp::PresentationResult) -> Result<Self, JsError> {
        let result = match value {
            equs_sdk::vc::oid4vp::PresentationResult::AuthorizationResponse(auth_resp) => {
                JsPresentationResult {
                    type_: PresentationResultType::AuthorizationResponse,
                    value: Some(serde_json::to_value(&auth_resp)?),
                }
            }
            equs_sdk::vc::oid4vp::PresentationResult::RedirectUri(uri) => JsPresentationResult {
                type_: PresentationResultType::RedirectUri,
                value: Some(serde_json::to_value(&uri)?),
            },
            equs_sdk::vc::oid4vp::PresentationResult::Presented => JsPresentationResult {
                type_: PresentationResultType::Presented,
                value: None,
            },
        };

        Ok(result)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JsVCStatusFormat {
    StatusListToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsVCStatus {
    pub format: JsVCStatusFormat,
    pub payload: serde_json::Value,
}

pub struct JsVcTslStatusPayload {
    pub status: TslVcStatusType,
    pub value: Option<u8>,
}

impl TryFrom<equs_sdk::vc::VCStatus> for JsVCStatus {
    type Error = JsError;

    fn try_from(value: equs_sdk::vc::VCStatus) -> Result<Self, Self::Error> {
        match value {
            equs_sdk::vc::VCStatus::StatusListToken(status) => {
                let payload_status = TslVcStatusType::from(status).to_string();
                let payload = match status {
                    status_list_token_jwt::VCStatus::Valid
                    | status_list_token_jwt::VCStatus::Invalid
                    | status_list_token_jwt::VCStatus::Suspended => {
                        json!({"status": payload_status})
                    }
                    status_list_token_jwt::VCStatus::AppSpecific(val) => {
                        json!({"status": payload_status, "value": val})
                    }
                };

                Ok(JsVCStatus {
                    format: JsVCStatusFormat::StatusListToken,
                    payload: serde_json::to_value(payload)?,
                })
            }
        }
    }
}

pub enum TslVcStatusType {
    VALID,
    INVALID,
    SUSPENDED,
    APPSPECIFIC,
}

impl TslVcStatusType {
    pub fn to_string(&self) -> String {
        match self {
            TslVcStatusType::VALID => "VALID".to_string(),
            TslVcStatusType::INVALID => "INVALID".to_string(),
            TslVcStatusType::SUSPENDED => "SUSPENDED".to_string(),
            TslVcStatusType::APPSPECIFIC => "APPSPECIFIC".to_string(),
        }
    }
}
impl From<equs_sdk::vc::TslVcStatus> for TslVcStatusType {
    fn from(value: equs_sdk::vc::TslVcStatus) -> Self {
        match value {
            equs_sdk::vc::TslVcStatus::Valid => Self::VALID,
            equs_sdk::vc::TslVcStatus::Invalid => Self::INVALID,
            equs_sdk::vc::TslVcStatus::Suspended => Self::SUSPENDED,
            equs_sdk::vc::TslVcStatus::AppSpecific(_) => Self::APPSPECIFIC,
        }
    }
}

pub fn convert_to_js_credentials_mapping(
    input: EqusSdkCredentialsMapping,
) -> Result<HashMap<String, CredentialsFindResult>, JsError> {
    let mut result: HashMap<String, CredentialsFindResult> = HashMap::new();

    for (id, cred_find_result) in input {
        result.insert(id, cred_find_result.try_into()?);
    }

    Ok(result)
}

fn convert_from_js_credential_mapping(
    input: HashMap<String, Vec<JsCredentialEntry>>,
) -> Result<HashMap<String, Vec<CredentialEntry>>, JsError> {
    let mut result = HashMap::new();
    for (key, value) in input {
        result.insert(
            key,
            value
                .into_iter()
                .map(|ce| ce.try_into())
                .collect::<Result<Vec<CredentialEntry>, JsError>>()?,
        );
    }

    Ok(result)
}

pub fn convert_hash_map_of_credentials_to_js_object(
    map: HashMap<String, CredentialsFindResult>,
) -> Result<JsValue, JsError> {
    let obj = Object::new();

    for (key, value) in map {
        Reflect::set(
            &obj,
            &JsValue::from_str(&key),
            &convert_to_opaque_object(value)?,
        )
        .map_err(|_| JsError::new("Failed at setting reflect in WASM conversion"))?;
    }

    Ok(obj.into())
}
