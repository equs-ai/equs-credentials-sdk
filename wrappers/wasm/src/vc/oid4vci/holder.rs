use crate::crypto::KeyMetadata;
use crate::utils;
use crate::vc::oid4vci::{
    CredentialResponse, OID4VCICredentialOffer, OID4VCIIssuerMetadata, TokenResponse,
};
use crate::vc::{Credential, CredentialMetadata, JsCredential};
use agent_sdk::vc;
use agent_sdk::vc::oid4vci::{
    AccessToken, AuthzFlow, CredentialOfferParams, CredentialResponseResolved, Holder,
    IssuerMetadata,
};
use async_trait::async_trait;
use js_sys::{Function, Promise};
use serde::Serialize;
use std::future::Future;
use std::io;
use std::pin::Pin;
use url::Url;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPE: &str = r#"
export type AuthCodeCallback = (url: string) => Promise<string>;
export type AuthCallback = (authorizationFlow: { type: "authorize", url: string } | { type: "preauthorized" }) => Promise<string>;
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "AuthCodeCallback")]
    pub type AuthCodeCallback;

    #[wasm_bindgen(typescript_type = "AuthCallback")]
    pub type AuthCallback;

    #[wasm_bindgen(method, js_name = "call")]
    pub fn call(this: &AuthCallback, authorization_flow: &JsValue) -> Promise;
}

impl AuthCodeCallback {
    pub async fn call_async(&self, url: &str) -> Result<String, JsError> {
        let func: &Function = self.unchecked_ref();
        let result = func
            .call1(&JsValue::NULL, &JsValue::from_str(url))
            .map_err(|err| {
                JsError::new(&err.as_string().unwrap_or_else(|| format!("{:?}", err)))
            })?;
        let promise: Promise = result.into();
        let js_value = JsFuture::from(promise).await.map_err(|err| {
            JsError::new(&err.as_string().unwrap_or_else(|| format!("{:?}", err)))
        })?;
        js_value
            .as_string()
            .ok_or_else(|| JsError::new("Expected a string result"))
    }
}

impl AuthCallback {
    pub async fn call_async(&self, auth_flow: AuthzFlow) -> Result<String, JsError> {
        let js_auth_flow = serde_wasm_bindgen::to_value(&JsAuthFlow::from(auth_flow))
            .map_err(|e| JsError::new(&e.to_string()))?;
        let func: &Function = self.unchecked_ref();
        let result = func.call1(&JsValue::NULL, &js_auth_flow).map_err(|err| {
            JsError::new(&err.as_string().unwrap_or_else(|| format!("{:?}", err)))
        })?;
        let promise: Promise = result.into();
        let js_value = JsFuture::from(promise).await.map_err(|err| {
            JsError::new(&err.as_string().unwrap_or_else(|| format!("{:?}", err)))
        })?;
        js_value
            .as_string()
            .ok_or_else(|| JsError::new("Expected a string result"))
    }
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum JsAuthFlow {
    #[serde(rename = "authorize")]
    Authorize { url: String },
    #[serde(rename = "preauthorized")]
    Preauthorized,
}

impl From<AuthzFlow> for JsAuthFlow {
    fn from(value: AuthzFlow) -> Self {
        match value {
            AuthzFlow::Authorize(url) => JsAuthFlow::Authorize {
                url: url.to_string(),
            },
            AuthzFlow::Preauthorized => JsAuthFlow::Preauthorized,
        }
    }
}

pub type AuthorizationCodeCallback =
    Box<dyn FnOnce(Url) -> Pin<Box<dyn Future<Output = Result<String, io::Error>>>>>;
pub type AuthorizationCallback =
    Box<dyn FnOnce(AuthzFlow) -> Pin<Box<dyn Future<Output = Result<String, io::Error>>>>>;

/// An async `oid4vci` `Holder` API.
///
/// Supports authorization and issuance flow according to the `oid4vci` standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// # Supported features
///
/// * retrieving metadata
/// * credential issuance (immediate)
/// * authorized code flow (using Pushed Authorization Request)
/// * pre-authorized code flow.
#[wasm_bindgen]
pub struct OID4VCIHolder(Box<dyn _HolderWrapperTrait>);

impl OID4VCIHolder {
    pub fn from_holder<H: Holder + 'static>(holder: H) -> OID4VCIHolder {
        OID4VCIHolder(Box::new(_HolderWrapper(holder)))
    }
}

#[wasm_bindgen]
impl OID4VCIHolder {
    /// Returns the `Metadata` of the `Issuer`.
    ///
    /// # Returns
    ///
    /// An `IssuerMetadata`.
    #[wasm_bindgen(js_name = getIssuerMetadata)]
    pub fn get_issuer_metadata(&self) -> Result<OID4VCIIssuerMetadata, JsError> {
        let issuer_metadata = self.0.get_issuer_metadata();

        utils::convert_to_opaque_object_unchecked(issuer_metadata)
    }

    /// Run Authorization Code Flow to authorize the `Holder`.
    ///
    /// Leverages Pushed Authorization Request endpoint, PKCE and CSRF tokens.
    ///
    /// # Arguments
    ///
    /// * `scope` - a scope for the desired `CredentialDefinition`s.
    /// * `authorization_callback` - a callback to retrieve an authorization code by the given `auth_url`.
    /// Requires application layer interaction.
    ///
    /// # Returns
    ///
    /// A `TokenResponse` with a valid token to be used for issuing a `Credential` on success.
    ///
    /// # Errors
    ///
    /// * Returns internal or protocol-specific error.
    #[wasm_bindgen(js_name = authzCodeFlowWithScope)]
    pub async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_code_callback: AuthCodeCallback,
    ) -> Result<TokenResponse, JsError> {
        self.0
            .authz_code_flow_with_scope(
                scope,
                Box::new(move |url| {
                    Box::pin(async move {
                        authorization_code_callback
                            .call_async(url.as_str())
                            .await
                            .map_err(|err| {
                                io::Error::new(io::ErrorKind::Other, format!("{:?}", err))
                            })
                    })
                }),
            )
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
            .and_then(utils::convert_to_opaque_object_unchecked)
    }

    /// Gets an access token using a resolved credential offer.
    ///
    /// This function handles the OAuth authorization process by:
    /// 1. Validating the credential offer parameters
    /// 2. Determining the appropriate authorization flow
    /// 3. Executing the authorization callback to obtain necessary codes
    /// 4. Exchanging the codes for an access token
    ///
    /// # Arguments
    ///
    /// * `offer_params` - A resolved credential offer containing optional authorization server endpoint,
    ///   supported grant types, and other metadata required for the token request.
    ///
    /// * `authorization_callback` - An asynchronous callback function that handles the user interaction
    ///   portion of the authorization flow. The callback receives an [AuthzFlow] enum indicating
    ///   whether to obtain an authorization code or transaction code. The callback must return
    ///   the appropriate code as a String.
    ///
    /// # Returns
    ///
    /// Returns a `Result<TokenResponse>` where `TokenResponse` contains:
    /// - An access token for credential issuance
    /// - Token type (usually "Bearer")
    /// - Expiration time (if provided)
    /// - Optional refresh token
    ///
    /// # Errors
    ///
    /// * Returns an internal or protocol-specific error.
    #[wasm_bindgen(js_name = getAccessToken)]
    pub async fn get_access_token(
        &self,
        offer_params: OID4VCICredentialOffer,
        authorization_callback: AuthCallback,
    ) -> Result<TokenResponse, JsError> {
        let offer_params = utils::convert_to_rust_object(offer_params)?;

        self.0
            .get_access_token(
                &offer_params,
                Box::new(move |authz_flow: AuthzFlow| {
                    Box::pin(async move {
                        authorization_callback
                            .call_async(authz_flow)
                            .await
                            .map_err(|err| {
                                io::Error::new(io::ErrorKind::Other, format!("{:?}", err))
                            })
                    })
                }),
            )
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
            .and_then(utils::convert_to_opaque_object_unchecked)
    }

    /// Request a `Credential` for the provided `CredentialDefinition`.
    ///
    /// Makes a call to an Issue Credential endpoint under the hood.
    ///
    /// Always generates and provides a `Proof of Possession` in the request.
    ///
    /// After getting the `Credential`, verifies it against the signature by resolving the issuer's DID.
    /// # Arguments
    ///
    /// * `token` - an access token.
    /// * `cred_def_id` - a `CredentialDefinition` ID.
    /// * `key_metadata` - a `KeyMetadata` for corresponding key to be used for signing operations.
    ///
    /// # Returns
    ///
    /// A `CredentialResponseResolved` (Immediate or Deferred) on success.
    /// Optionally includes `NonceData` for the next requests.
    ///
    /// # Errors
    ///
    /// * Returns an internal or protocol-specific error.
    #[wasm_bindgen(js_name = requestCredential)]
    pub async fn request_credential(
        &self,
        token: String,
        cred_def_id: String,
        key_metadata: KeyMetadata,
    ) -> Result<CredentialResponse, JsError> {
        let token = serde_json::from_value(serde_json::Value::String(token))?;
        let key_metadata = utils::convert_to_rust_object(key_metadata)?;

        self.0
            .request_credential(&token, &cred_def_id, &key_metadata)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
            .and_then(TryInto::try_into)
    }

    /// Store a `Credential`.
    ///
    /// This method will store the `credential` into the `Vault` under the hood.
    ///
    /// # Arguments
    ///
    /// * `credential` - a `Credential` to save.
    /// * `credential_metadata` - the corresponding `CredentialMetadata`.
    ///
    /// # Returns
    ///
    /// `id` on success.
    ///
    /// # Errors
    ///
    /// * Returns an internal error.
    #[wasm_bindgen(js_name = storeCredential)]
    pub async fn store_credential(
        &self,
        credential: Credential,
        credential_metadata: CredentialMetadata,
    ) -> Result<String, JsError> {
        let js_credential: JsCredential = utils::convert_to_rust_object(credential)?;
        let credential = js_credential.try_into()?;
        let credential_metadata = utils::convert_to_rust_object(credential_metadata)?;

        self.0
            .store_credential(&credential, &credential_metadata)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }
}

#[async_trait(?Send)]
trait _HolderWrapperTrait {
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: AuthorizationCodeCallback,
    ) -> vc::oid4vci::Result<vc::oid4vci::TokenResponse>;

    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        key_metadata: &vc::core::KeyMetadata,
    ) -> vc::oid4vci::Result<CredentialResponseResolved>;

    async fn store_credential(
        &self,
        credential: &vc::Credential,
        credential_metadata: &vc::CredentialMetadata,
    ) -> vc::oid4vci::Result<String>;

    async fn get_access_token(
        &self,
        offer_params: &CredentialOfferParams,
        authorization_callback: AuthorizationCallback,
    ) -> vc::oid4vci::Result<vc::oid4vci::TokenResponse>;
}

pub struct _HolderWrapper<H: Holder>(pub(crate) H);

#[async_trait(?Send)]
impl<H: Holder> _HolderWrapperTrait for _HolderWrapper<H> {
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.0.get_issuer_metadata()
    }

    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: AuthorizationCodeCallback,
    ) -> vc::oid4vci::Result<vc::oid4vci::TokenResponse> {
        self.0
            .authz_code_flow_with_scope(scope, authorization_callback)
            .await
    }

    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        key_metadata: &vc::core::KeyMetadata,
    ) -> vc::oid4vci::Result<CredentialResponseResolved> {
        self.0
            .request_credential(token, cred_def_id, key_metadata)
            .await
    }

    async fn store_credential(
        &self,
        credential: &vc::Credential,
        credential_metadata: &vc::CredentialMetadata,
    ) -> vc::oid4vci::Result<String> {
        self.0
            .store_credential(credential, credential_metadata)
            .await
    }

    async fn get_access_token(
        &self,
        offer_params: &CredentialOfferParams,
        authorization_callback: AuthorizationCallback,
    ) -> vc::oid4vci::Result<vc::oid4vci::TokenResponse> {
        self.0
            .get_access_token(offer_params, authorization_callback)
            .await
    }
}
