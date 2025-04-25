use crate::utils::{from_json_object, to_json_object};
use crate::vc::core::{JsCredential, JsCredentialMetadata, JsKeyMetadata};
use crate::vc::JsonObject;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vci::{
    AccessToken, AuthzFlow, CredentialOfferParams, CredentialResponseResolved, CredentialResult,
    Holder, IssuerMetadata, TokenResponse,
};
use agent_sdk::vc::{oid4vci, Credential, CredentialMetadata};
use async_trait::async_trait;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi::Either;
use napi_derive::napi;
use std::future::Future;
use std::io;
use std::pin::Pin;
use url::Url;

pub type AuthorizationCodeCallback =
    Box<dyn FnOnce(Url) -> Pin<Box<dyn Future<Output = Result<String, io::Error>> + Send>> + Send>;
pub type AuthorizationCallback = Box<
    dyn FnOnce(AuthzFlow) -> Pin<Box<dyn Future<Output = Result<String, io::Error>> + Send>> + Send,
>;

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
/// * pre-authorized code flow
///
/// @property getIssuerMetadata - {@link OID4VCIHolder.getIssuerMetadata}
/// @property authzCodeFlowWithScope - {@link OID4VCIHolder.authzCodeFlowWithScope}
/// @property getAccessToken - {@link OID4VCIHolder.getAccessToken}
/// @property requestCredential - {@link OID4VCIHolder.requestCredential}
/// @property storeCredential - {@link OID4VCIHolder.storeCredential}
#[napi]
pub struct OID4VCIHolder(Box<dyn _HolderWrapperTrait>);

impl OID4VCIHolder {
    pub fn from_holder<H: Holder + 'static>(holder: H) -> OID4VCIHolder {
        OID4VCIHolder(Box::new(_HolderWrapper(holder)))
    }
}

#[napi]
impl OID4VCIHolder {
    /// @returns {@link OID4VCIIssuerMetadata}
    #[napi(ts_return_type = "OID4VCIIssuerMetadata")]
    pub fn get_issuer_metadata(&self) -> napi::Result<JsonObject> {
        let issuer_metadata = self.0.get_issuer_metadata();

        to_json_object(issuer_metadata)
    }

    /// Run Authorization Code Flow to authorize the `OID4VCIHolder`.
    /// Leverages Pushed Authorization Request endpoint, PKCE and CSRF tokens.
    ///
    /// Requires application layer interaction.
    ///
    /// @param {string} `scope` - a scope for the desired {@link CredentialDefinition}`s.
    /// @param {(url: string) => Promise<string>} `authorizationCodeCallback` - a callback to retrieve an authorization code by the given `auth_url`.
    ///
    /// @returns {TokenResponse} - A {@link TokenResponse} with a valid token to be used for issuing a {@link Credential} on success.
    #[napi(
        ts_args_type = "scope: string, authorizationCodeCallback: (url: string) => Promise<string>",
        ts_return_type = "Promise<TokenResponse>"
    )]
    pub async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_code_callback: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    ) -> napi::Result<JsonObject> {
        self.0
            .authz_code_flow_with_scope(
                scope,
                Box::new(move |url| {
                    Box::pin(async move {
                        let result = authorization_code_callback
                            .call_async::<Promise<String>>(url.to_string())
                            .await
                            .unwrap()
                            .await;

                        match result {
                            Ok(s) => Ok(s),
                            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e))),
                        }
                    })
                }),
            )
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))
            .and_then(to_json_object)
    }

    /// Gets an access token using a resolved credential offer.
    ///
    /// This function handles the OAuth authorization process by:
    /// 1. Validating the credential offer parameters
    /// 2. Determining the appropriate authorization flow
    /// 3. Executing the authorization callback to obtain necessary codes
    /// 4. Exchanging the codes for an access token
    ///
    /// @param {OID4VCICredentialOffer} offer_params - A resolved credential offer containing optional authorization server endpoint, supported grant types, and other metadata required for the token request.
    ///
    /// @param {(authorization_flow: { type: "authorize", url: string } | { type: "preauthorized" }) => Promise<string>} authorization_callback - An asynchronous callback function that handles the user interaction
    ///   portion of the authorization flow. The callback receives an `AuthzFlow` enum indicating whether to obtain an authorization code or transaction code. The callback must return the appropriate code as a String.
    ///
    /// @returns {TokenResponse}
    #[napi(
        ts_args_type = "offer_params: OID4VCICredentialOffer, authorization_callback: (authorization_flow: { type: \"authorize\", url: string } | { type: \"preauthorized\" }) => Promise<string>",
        ts_return_type = "Promise<TokenResponse>"
    )]
    pub async fn get_access_token(
        &self,
        offer_params: JsonObject,
        authorization_callback: ThreadsafeFunction<JsonObject, ErrorStrategy::Fatal>,
    ) -> napi::Result<JsonObject> {
        self.0
            .get_access_token(
                &from_json_object(offer_params)?,
                Box::new(move |authz_flow: AuthzFlow| {
                    let mut authz_flow_json_object = JsonObject::new();

                    match authz_flow {
                        AuthzFlow::Preauthorized => {
                            authz_flow_json_object.insert(
                                "type".to_string(),
                                serde_json::Value::String("preauthorized".to_string()),
                            );
                        }
                        AuthzFlow::Authorize(url) => {
                            authz_flow_json_object.insert(
                                "type".to_string(),
                                serde_json::Value::String("authorize".to_string()),
                            );
                            authz_flow_json_object.insert(
                                "url".to_string(),
                                serde_json::Value::String(url.to_string()),
                            );
                        }
                    };

                    Box::pin(async move {
                        let result = authorization_callback
                            .call_async::<Promise<String>>(authz_flow_json_object)
                            .await
                            .unwrap()
                            .await;

                        match result {
                            Ok(s) => Ok(s),
                            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e))),
                        }
                    })
                }),
            )
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))
            .and_then(to_json_object)
    }

    /// Request a {@link Credential} for the provided {@link CredentialDefinition}.
    ///
    /// Makes a call to an Issue Credential endpoint under the hood.
    ///
    /// Always generates and provides a `Proof of Possession` in the request.
    ///
    /// After getting the {@link Credential}, verifies it against the signature by resolving the issuer's DID.
    ///
    /// @param {string} token - an access token.
    /// @param {string} credDefId - a {@link CredentialDefinition} ID.
    /// @param {KeyMetadata} keyMetadata - a {@link KeyMetadata} for corresponding key to be used for signing operations.
    ///
    /// @returns {CredentialResponse} - A {@link CredentialResponse} (Immediate or Deferred) on success.
    #[napi]
    pub async fn request_credential(
        &self,
        token: String,
        cred_def_id: String,
        key_metadata: JsKeyMetadata,
    ) -> napi::Result<CredentialResponse> {
        let token = serde_json::from_value(serde_json::Value::String(token))?;
        let key_metadata = key_metadata.into();

        self.0
            .request_credential(&token, &cred_def_id, &key_metadata)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))
            .and_then(TryInto::try_into)
    }

    /// Store a {@link Credential}.
    ///
    /// This method will store the `credential` into the {@link Vault} under the hood.
    ///
    /// @param {Credential} credential - a {@link Credential} to save.
    /// @param {CredentialMetadata} credentialMetadata - the corresponding {@link CredentialMetadata}.
    ///
    /// @returns {string} - `id` on success.
    #[napi]
    pub async fn store_credential(
        &self,
        credential: JsCredential,
        credential_metadata: JsCredentialMetadata,
    ) -> napi::Result<String> {
        self.0
            .store_credential(&credential.try_into()?, &credential_metadata.into())
            .await
            .map_err(|err| napi::Error::from_reason(format!("{:?}", err)))
    }
}

#[napi(object)]
pub struct CredentialDeferred {
    #[napi(js_name = "transaction_id")]
    pub transaction_id: String,
}

#[napi(object)]
pub struct CredentialImmediate {
    pub credentials: Vec<JsCredential>,
    #[napi(js_name = "notification_id")]
    pub notification_id: Option<String>,
}

#[napi(object)]
pub struct CredentialResponse {
    pub data: Either<CredentialDeferred, CredentialImmediate>,
}

impl TryFrom<CredentialResponseResolved> for CredentialResponse {
    type Error = napi::Error;

    fn try_from(value: CredentialResponseResolved) -> napi::Result<Self> {
        let data = match value.data {
            CredentialResult::Deferred { transaction_id } => {
                Either::A(CredentialDeferred { transaction_id })
            }
            CredentialResult::Credential {
                credentials,
                notification_id,
            } => {
                let mut creds: Vec<JsCredential> = vec![];
                for credential in credentials {
                    creds.push(credential.try_into()?);
                }

                Either::B(CredentialImmediate {
                    credentials: creds,
                    notification_id,
                })
            }
        };

        Ok(Self { data })
    }
}

#[async_trait]
trait _HolderWrapperTrait: Send + Sync {
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: AuthorizationCodeCallback,
    ) -> oid4vci::Result<TokenResponse>;

    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        key_metadata: &KeyMetadata,
    ) -> oid4vci::Result<CredentialResponseResolved>;

    async fn store_credential(
        &self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> oid4vci::Result<String>;

    async fn get_access_token(
        &self,
        offer_params: &CredentialOfferParams,
        authorization_callback: AuthorizationCallback,
    ) -> oid4vci::Result<TokenResponse>;
}

pub struct _HolderWrapper<H: Holder>(pub(crate) H);

#[async_trait]
impl<H: Holder> _HolderWrapperTrait for _HolderWrapper<H> {
    fn get_issuer_metadata(&self) -> IssuerMetadata {
        self.0.get_issuer_metadata()
    }

    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: AuthorizationCodeCallback,
    ) -> oid4vci::Result<TokenResponse> {
        self.0
            .authz_code_flow_with_scope(scope, authorization_callback)
            .await
    }

    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        key_metadata: &KeyMetadata,
    ) -> oid4vci::Result<CredentialResponseResolved> {
        self.0
            .request_credential(token, cred_def_id, key_metadata)
            .await
    }

    async fn store_credential(
        &self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> oid4vci::Result<String> {
        self.0
            .store_credential(credential, credential_metadata)
            .await
    }

    async fn get_access_token(
        &self,
        offer_params: &CredentialOfferParams,
        authorization_callback: AuthorizationCallback,
    ) -> oid4vci::Result<TokenResponse> {
        self.0
            .get_access_token(offer_params, authorization_callback)
            .await
    }
}
