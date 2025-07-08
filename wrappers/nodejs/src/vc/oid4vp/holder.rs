use crate::utils::{from_json_object, parse_url_arg, to_json_object};
use crate::vault::{JsCredentialEntry, JsCredentialsFindResult};
use crate::vc::JsonObject;
use crate::vc::core::JsKeyMetadata;
use agent_sdk::vault::CredentialEntry;
use agent_sdk::vc::oid4vp::{
    AuthorizationResponseMetadata, CredentialMapping, CredentialsMapping, ResolvedAuthRequest,
};
use agent_sdk::vc::oid4vp::{Holder, IdTokenMetadata};
use napi::{Error, Result};
use napi_derive::napi;
use std::collections::HashMap;
use time::ext::NumericalDuration;
use url::Url;

/// The `OID4VP` `Holder` API.
/// This is an inner holder api used by the main wrapper in Node.js implementation
/// Supports presentation flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// @property getAuthorizationRequest - {@link InnerOID4VPHolder.getAuthorizationRequest}
/// @property presentCredentialsAuto - {@link InnerOID4VPHolder.presentCredentialsAuto}
/// @property findVcsForPresentation - {@link InnerOID4VPHolder.findVcsForPresentation}
/// @property presentCredentials - {@link InnerOID4VPHolder.presentCredentials}
/// @property declineAuthorizationRequest - {@link InnerOID4VPHolder.declineAuthorizationRequest}
#[napi]
pub struct InnerOID4VPHolder(Box<dyn Holder>);

impl InnerOID4VPHolder {
    pub fn from_holder<H: Holder + 'static>(holder: H) -> InnerOID4VPHolder {
        InnerOID4VPHolder(Box::new(holder))
    }
}

#[napi]
impl InnerOID4VPHolder {
    /// Fetches the `OID4VP` authorization request object from the provided URI.
    /// If the validation of authorization request fails then related `ProtocolError` response will be sent to the `response_uri` endpoint
    ///
    /// @param {string} requestUri - a request URI provided by the authorization URL.
    ///
    /// @returns {AuthorizationRequest} A {@link AuthorizationRequest} with the presentation definition and other relevant details on success.
    #[napi]
    pub async fn get_authorization_request(
        &self,
        request_uri: String,
    ) -> Result<_AuthorizationRequest> {
        self.0
            .get_authorization_request(&parse_url_arg(&request_uri)?)
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))
            .and_then(|result| result.try_into())
    }

    /// Automatically presents credentials to the Verifier based on the authorization request.
    ///
    /// This method selects the first appropriate credential that matches the requirements of the authorization request.
    /// To present specific credentials, use {@link OID4VPHolder.findVcsForPresentation} to discover suitable credentials and
    /// {@link OID4VPHolder.presentCredentials} to manually present them.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request containing the presentation requirements.
    /// @param {AuthorizationResponseMetadata} authResponseMetadata - the metadata for the authorization response.
    ///
    /// @returns {string | null}
    /// * A redirect URL if the presentation is successful
    /// * `null` on success without redirection.
    #[napi]
    pub async fn present_credentials_auto(
        &self,
        auth_request: _AuthorizationRequest,
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

    /// Finds verifiable credentials required for the presentation based on the authorization request.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request containing the presentation requirements.
    ///
    /// @returns {Record<string, Array<CredentialEntry>}
    /// * An object of credentials that satisfy the authorization request's requirements.
    /// * If no matching credentials are found, an empty object is returned.
    #[napi]
    pub async fn find_vcs_for_presentation(
        &self,
        auth_request: _AuthorizationRequest,
    ) -> Result<HashMap<String, JsCredentialsFindResult>> {
        let credentials_mapping = self
            .0
            .find_vcs_for_presentation(&auth_request.try_into()?)
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        convert_to_js_credentials_mapping(credentials_mapping)
    }

    /// Manually presents credentials to the Verifier.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request.
    /// @param {Record<string, CredentialEntry>} credentialMapping - the map of credentials required for the presentation.
    /// @param {AuthorizationResponseMetadata} authResponseMetadata -the authorization response metadata.
    ///
    /// @returns {string | null}
    /// * A redirect URL if the presentation is successful
    /// * `null` on success without redirection.
    #[napi]
    pub async fn present_credentials(
        &self,
        auth_request: _AuthorizationRequest,
        credential_mapping: HashMap<String, JsCredentialEntry>,
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

    /// Decline the authorization request by sending authorization error response to the `response_uri` endpoint.
    ///
    /// @returns {string | null}
    /// An optional redirect URL(in case of Same Device Flow) where the error response is embedded as a fragment.
    ///
    /// @param {_AuthorizationRequest} authRequest - the resolved authorization request.
    #[napi]
    pub async fn decline_authorization_request(
        &self,
        auth_request: _AuthorizationRequest,
    ) -> Result<Option<String>> {
        let auth_request: ResolvedAuthRequest = auth_request.try_into()?;
        let redirect_url = self
            .0
            .decline_authorization_request(&auth_request)
            .await
            .map_err(|err| Error::from_reason(err.to_string()))?;

        Ok(redirect_url.map(|url| url.to_string()))
    }
}

#[napi(object, js_name = "_AuthorizationRequest")]
pub struct _AuthorizationRequest {
    #[napi(js_name = "client_id")]
    pub client_id: String,
    #[napi(ts_type = "ClientMetadata", js_name = "client_metadata")]
    pub client_metadata: JsonObject,
    #[napi(
        ts_type = "ResolvedPresentationQuery",
        js_name = "resolved_presentation_query"
    )]
    pub resolved_presentation_query: JsonObject,
    pub nonce: String,
    #[napi(js_name = "response_type")]
    pub response_type: String,
    #[napi(js_name = "response_mode")]
    pub response_mode: String,
    #[napi(js_name = "response_uri")]
    pub response_uri: String,
    pub state: Option<String>,
}

impl TryFrom<_AuthorizationRequest> for ResolvedAuthRequest {
    type Error = Error;

    fn try_from(value: _AuthorizationRequest) -> Result<Self> {
        Ok(ResolvedAuthRequest {
            client_id: value.client_id,
            client_metadata: from_json_object(value.client_metadata)?,
            resolved_presentation_query: from_json_object(value.resolved_presentation_query)?,
            nonce: serde_json::from_value(serde_json::Value::String(value.nonce))?,
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: parse_url_arg(&value.response_uri)?,
            state: value.state,
        })
    }
}

impl TryFrom<ResolvedAuthRequest> for _AuthorizationRequest {
    type Error = Error;

    fn try_from(value: ResolvedAuthRequest) -> Result<Self> {
        Ok(_AuthorizationRequest {
            client_id: value.client_id,
            client_metadata: to_json_object(&value.client_metadata)?,
            resolved_presentation_query: to_json_object(&value.resolved_presentation_query)?,
            nonce: value.nonce.secret().to_string(),
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: value.response_uri.to_string(),
            state: value.state,
        })
    }
}

/// Metadata for an Authorization Response.
///
/// @property {Record<string, Array<string>> | null} [claimsToExclude] - map of claims divided by input descriptors that need to be excluded.
/// @property {IdTokenMetadata | null} [idTokenMetadata] - metadata containing the signing key and lifetime for the SIOP ID token
///
#[napi(object, js_name = "AuthorizationResponseMetadata")]
pub struct JsAuthorizationResponseMetadata {
    pub claims_to_exclude: Option<HashMap<String, Vec<String>>>,
    pub id_token_metadata: Option<JsIdTokenMetadata>,
}

#[napi(object, js_name = "IdTokenMetadata")]
pub struct JsIdTokenMetadata {
    pub key_metadata: JsKeyMetadata,
    pub lifetime: i64,
}

impl TryFrom<JsAuthorizationResponseMetadata> for AuthorizationResponseMetadata {
    type Error = Error;
    fn try_from(value: JsAuthorizationResponseMetadata) -> Result<Self> {
        Ok(Self {
            claims_to_exclude: value
                .claims_to_exclude
                .map(|cte| from_json_object(to_json_object(cte)?))
                .transpose()?,
            id_token_metadata: value.id_token_metadata.map(|idt| IdTokenMetadata {
                key_metadata: idt.key_metadata.into(),
                lifetime: idt.lifetime.seconds(),
            }),
        })
    }
}

fn convert_to_js_credentials_mapping(
    input: CredentialsMapping,
) -> Result<HashMap<String, JsCredentialsFindResult>> {
    let mut result = HashMap::new();

    for (key, value) in input {
        result.insert(key, value.try_into()?);
    }

    Ok(result)
}

fn convert_from_js_credential_mapping(
    input: HashMap<String, JsCredentialEntry>,
) -> Result<CredentialMapping> {
    input
        .into_iter()
        .map(|(key, val)| {
            let converted_val: Result<CredentialEntry> = val.try_into();
            converted_val.map(|v| (key, v))
        })
        .collect()
}
