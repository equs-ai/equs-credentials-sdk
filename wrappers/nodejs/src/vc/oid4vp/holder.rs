use agent_sdk::vault::CredentialEntry;
use agent_sdk::vc::oid4vp::Holder;
use agent_sdk::vc::oid4vp::{
    AuthorizationResponseMetadata, CredentialMapping, ResolvedAuthRequest,
};
use napi::{Error, Result};
use napi_derive::napi;
use std::collections::HashMap;
use url::Url;

use crate::utils::{from_json_object, parse_url_arg, to_json_object};
use crate::vault::JsCredentialEntry;
use crate::vc::JsonObject;

#[napi]
pub struct OID4VPHolder(Box<dyn Holder>);

impl OID4VPHolder {
    pub fn from_holder<H: Holder + 'static>(holder: H) -> OID4VPHolder {
        OID4VPHolder(Box::new(holder))
    }
}

#[napi]
impl OID4VPHolder {
    #[napi]
    pub async fn get_authorization_request(
        &self,
        request_uri: String,
    ) -> Result<AuthorizationRequest> {
        self.0
            .get_authorization_request(&parse_url_arg(&request_uri)?)
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))
            .and_then(|result| result.try_into())
    }

    #[napi]
    pub async fn present_credentials_auto(
        &self,
        auth_request: AuthorizationRequest,
        auth_response_metadata: JsAuthorizationResponseMetadata,
    ) -> Result<Option<String>> {
        let result = self
            .0
            .present_credentials_auto(
                &auth_request.try_into()?,
                &auth_response_metadata.try_into()?,
            )
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(result.map(|url: Url| url.to_string()))
    }

    #[napi]
    pub async fn find_vcs_for_presentation(
        &self,
        auth_request: AuthorizationRequest,
    ) -> Result<HashMap<String, Vec<JsCredentialEntry>>> {
        let credential_mapping = self
            .0
            .find_vcs_for_presentation(&auth_request.try_into()?)
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        convert_to_js_credential_mapping(credential_mapping)
    }

    #[napi]
    pub async fn present_credentials(
        &self,
        auth_request: AuthorizationRequest,
        credential_mapping: HashMap<String, Vec<JsCredentialEntry>>,
        auth_response_metadata: JsAuthorizationResponseMetadata,
    ) -> Result<Option<String>> {
        let result = self
            .0
            .present_credentials(
                &auth_request.try_into()?,
                &convert_from_js_credential_mapping(credential_mapping)?,
                &auth_response_metadata.try_into()?,
            )
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(result.map(|url: Url| url.to_string()))
    }
}

#[napi(object)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub presentation_definition: JsonObject,
    pub nonce: String,
    pub response_mode: String,
    pub response_uri: String,
}

impl TryFrom<AuthorizationRequest> for ResolvedAuthRequest {
    type Error = Error;

    fn try_from(value: AuthorizationRequest) -> Result<Self> {
        Ok(ResolvedAuthRequest {
            client_id: value.client_id,
            presentation_definition: from_json_object(value.presentation_definition)?,
            nonce: serde_json::from_value(serde_json::Value::String(value.nonce))?,
            response_mode: value.response_mode.into(),
            response_uri: parse_url_arg(&value.response_uri)?,
        })
    }
}

impl TryFrom<ResolvedAuthRequest> for AuthorizationRequest {
    type Error = Error;

    fn try_from(value: ResolvedAuthRequest) -> Result<Self> {
        Ok(AuthorizationRequest {
            client_id: value.client_id,
            presentation_definition: to_json_object(&value.presentation_definition)?,
            nonce: value.nonce.secret().to_string(),
            response_mode: value.response_mode.into(),
            response_uri: value.response_uri.to_string(),
        })
    }
}

#[napi(object)]
pub struct JsAuthorizationResponseMetadata {
    pub claims_to_exclude: Option<HashMap<String, Vec<String>>>,
}

impl TryFrom<JsAuthorizationResponseMetadata> for AuthorizationResponseMetadata {
    type Error = Error;
    fn try_from(value: JsAuthorizationResponseMetadata) -> Result<Self> {
        Ok(Self {
            claims_to_exclude: value
                .claims_to_exclude
                .map(|cte| from_json_object(to_json_object(cte)?))
                .transpose()?,
        })
    }
}

fn convert_to_js_credential_mapping(
    input: CredentialMapping,
) -> Result<HashMap<String, Vec<JsCredentialEntry>>> {
    input
        .into_iter()
        .map(|(key, vec)| {
            let converted_vec: Result<Vec<JsCredentialEntry>> =
                vec.into_iter().map(|entry| entry.try_into()).collect();
            converted_vec.map(|vec| (key, vec))
        })
        .collect()
}

fn convert_from_js_credential_mapping(
    input: HashMap<String, Vec<JsCredentialEntry>>,
) -> Result<CredentialMapping> {
    input
        .into_iter()
        .map(|(key, vec)| {
            let converted_vec: Result<Vec<CredentialEntry>> =
                vec.into_iter().map(|entry| entry.try_into()).collect();
            converted_vec.map(|v| (key, v))
        })
        .collect()
}
