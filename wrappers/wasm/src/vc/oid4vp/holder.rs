use agent_sdk::vc::oid4vp::Holder;
use std::collections::HashMap;
use url::Url;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

use crate::utils;
use crate::vc::oid4vp::{
    AuthorizationRequest, AuthorizationResponseMetadata, CredentialMapping, CredentialsMapping,
};
use crate::vc::JsCredentialEntry;

/// The `OID4VP` `Holder` API.
///
/// Supports presentation flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// # Features
///
/// * Fetches authorization requests from verifiers.
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
    /// A redirect URL if the presentation is successful, or `None` on success without redirection.
    ///
    /// # Errors
    ///
    /// * Returns an internal or protocol-specific error.
    #[wasm_bindgen(js_name = presentCredentialsAuto)]
    pub async fn present_credentials_auto(
        &self,
        auth_request: AuthorizationRequest,
        metadata: Option<AuthorizationResponseMetadata>,
    ) -> Result<Option<String>, JsError> {
        let auth_request = utils::convert_to_rust_object(auth_request)?;
        let metadata = metadata
            .map(utils::convert_to_rust_object)
            .transpose()?
            .unwrap_or_else(|| agent_sdk::vc::oid4vp::AuthorizationResponseMetadata::default());

        let result = self
            .0
            .present_credentials_auto(&auth_request, &metadata)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        Ok(result.map(|url: Url| url.to_string()))
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
        let auth_request = utils::convert_to_rust_object(auth_request)?;

        let credentials_mapping = self
            .0
            .find_vcs_for_presentation(&auth_request)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        let js_value = convert_to_js_credentials_mapping(credentials_mapping)?;

        utils::convert_to_opaque_object_unchecked(js_value)
    }

    /// Manually presents credentials to the Verifier.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request.
    /// * `credential_mapping` - the map of credentials required for the presentation.
    /// * `metadata` -the authorization response metadata.
    ///
    /// # Returns
    ///
    /// A redirect URL if the presentation is successful, or `None` on success without redirection.
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
    ) -> Result<Option<String>, JsError> {
        let auth_request = utils::convert_to_rust_object(auth_request)?;
        let credential_mapping = utils::convert_to_rust_object(credential_mapping)
            .map_err(|err| JsError::new(&format!("{:?}", err)))
            .and_then(convert_from_js_credential_mapping)?;
        let metadata = metadata
            .map(utils::convert_to_rust_object)
            .transpose()?
            .unwrap_or_else(|| agent_sdk::vc::oid4vp::AuthorizationResponseMetadata::default());

        let result = self
            .0
            .present_credentials(&auth_request, &credential_mapping, &metadata)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        Ok(result.map(|url: Url| url.to_string()))
    }
}

fn convert_to_js_credentials_mapping(
    input: HashMap<String, Vec<agent_sdk::vault::CredentialEntry>>,
) -> Result<HashMap<String, Vec<JsCredentialEntry>>, JsError> {
    input
        .into_iter()
        .map(|(key, vec)| {
            let converted_vec: Result<Vec<JsCredentialEntry>, JsError> =
                vec.into_iter().map(TryInto::try_into).collect();
            converted_vec.map(|vec| (key, vec))
        })
        .collect()
}

fn convert_from_js_credential_mapping(
    input: HashMap<String, JsCredentialEntry>,
) -> Result<HashMap<String, agent_sdk::vault::CredentialEntry>, JsError> {
    input
        .into_iter()
        .map(|(key, val)| {
            let converted_val: Result<agent_sdk::vault::CredentialEntry, JsError> = val.try_into();

            converted_val.map(|v| (key, v))
        })
        .collect()
}
