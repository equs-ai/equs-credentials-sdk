use crate::common::{Error, JsonValue, Result};
use crate::vc::oid4vci::{CredentialResponse, TokenResponse};
use crate::vc::{Credential, CredentialMetadata};
use agent_sdk::vc::oid4vci::Notification as AsdkNotification;
use agent_sdk::vc::oid4vci::NotificationEvent as AsdkNotificationEvent;
use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use url::Url;

/// Handler for the authorization code grant's user interaction step; must be safe to call from any
/// thread.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait AuthCodeCallback: Send + Sync {
    /// Directs the user to the authorization URL and returns the resulting code.
    ///
    /// # Arguments
    /// * `url` - the authorization URL to present to the user
    ///
    /// # Returns
    /// The authorization code alone, not the redirect URL.
    ///
    /// # Errors
    /// * `Error` - the user cancelled, or the redirect carried no code
    async fn authenticate(&self, url: String) -> Result<String>;
}

#[derive(uniffi::Enum)]
pub enum AuthzFlow {
    Authorize(String),
    Preauthorized,
}

impl From<agent_sdk::vc::oid4vci::AuthzFlow> for AuthzFlow {
    fn from(flow: agent_sdk::vc::oid4vci::AuthzFlow) -> Self {
        match flow {
            agent_sdk::vc::oid4vci::AuthzFlow::Authorize(url) => {
                AuthzFlow::Authorize(url.to_string())
            }
            agent_sdk::vc::oid4vci::AuthzFlow::Preauthorized => AuthzFlow::Preauthorized,
        }
    }
}

/// Handler covering both grants, used by `OID4VCIHolder.getAccessToken`; must be safe to call from
/// any thread.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait AuthCallback: Send + Sync {
    /// Carries out the user interaction the flow describes and returns the resulting code.
    ///
    /// # Arguments
    /// * `authz_flow` - the grant to carry out
    ///
    /// # Returns
    /// The authorization code for `Authorize`, or the transaction code for `Preauthorized`.
    ///
    /// # Errors
    /// * `Error` - the user cancelled, or no code could be obtained
    async fn authenticate(&self, authz_flow: AuthzFlow) -> Result<String>;
}

#[derive(uniffi::Object)]
pub struct OID4VCIHolder(Box<dyn _HolderWrapperTrait>);

impl OID4VCIHolder {
    pub fn new(holder: impl agent_sdk::vc::oid4vci::Holder + 'static) -> Self {
        OID4VCIHolder(Box::new(_HolderWrapper(holder)))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl OID4VCIHolder {
    /// Returns the `Metadata` of the `Issuer`.
    ///
    /// # Returns
    ///
    /// An `IssuerMetadata`.
    pub fn get_issuer_metadata(&self) -> Result<JsonValue> {
        let issuer_metadata = self.0.get_issuer_metadata();

        serde_json::to_value(issuer_metadata)
            .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
    }

    /// Run Authorization Code Flow to authorize the `Holder`.
    ///
    /// Leverages Pushed Authorization Request endpoint, PKCE and CSRF tokens.
    ///
    /// # Arguments
    ///
    /// * `scope` - a scope for the desired `CredentialDefinition`s.
    /// * `authorization_callback` - a callback to retrieve an authorization code by the given `auth_url`.
    ///   Requires application layer interaction.
    ///
    /// # Returns
    ///
    /// A `TokenResponse` with a valid token to be used for issuing a `Credential` on success.
    ///
    /// # Errors
    ///
    /// * Returns internal or protocol-specific error.
    pub async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_code_callback: Arc<dyn AuthCodeCallback>,
    ) -> Result<TokenResponse> {
        self.0
            .authz_code_flow_with_scope(
                scope,
                Box::new(move |url| {
                    Box::pin(async move {
                        authorization_code_callback
                            .authenticate(url.to_string())
                            .await
                            .map_err(|err| io::Error::other(format!("{:?}", err)))
                    })
                }),
            )
            .await
            .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
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
    ///   portion of the authorization flow. The callback receives an `AuthzFlow` enum indicating
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
    pub async fn get_access_token(
        &self,
        offer_params: JsonValue,
        authorization_callback: Arc<dyn AuthCallback>,
    ) -> Result<TokenResponse> {
        let offer_params = serde_json::from_value(offer_params)
            .map_err(|err| Error::OID4VCIInternal(format!("{err}")))?;

        self.0
            .get_access_token(
                &offer_params,
                Box::new(move |authz_flow: agent_sdk::vc::oid4vci::AuthzFlow| {
                    Box::pin(async move {
                        authorization_callback
                            .authenticate(authz_flow.into())
                            .await
                            .map_err(|err| io::Error::other(format!("{:?}", err)))
                    })
                }),
            )
            .await
            .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
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
    /// * `key_metadata` - a slice of `KeyMetadata` for corresponding keys to be used for signing operations.
    ///
    /// # Returns
    ///
    /// A `CredentialResponseResolved` (Immediate or Deferred) on success.
    ///
    /// # Errors
    ///
    /// * Returns an internal or protocol-specific error.
    pub async fn request_credential(
        &self,
        token: String,
        cred_def_id: String,
        key_metadata: Vec<agent_sdk::vc::core::KeyMetadata>,
    ) -> Result<CredentialResponse> {
        let token = serde_json::from_value(serde_json::Value::String(token))
            .map_err(|err| Error::OID4VCIInternal(err.to_string()))?;

        self.0
            .request_credential(&token, &cred_def_id, key_metadata.as_slice())
            .await
            .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
    }

    /// Request a `Credential` which issuance is deferred.
    ///
    /// Calls Deferred Credential Endpoint of the Issuer.
    ///
    /// # Arguments
    ///
    /// * `token` - an access token.
    /// * `transaction_id` - transaction id returned from the last
    ///   credential or deferred credential request.
    /// # Returns
    ///
    /// A `CredentialResponseResolved` (Immediate or Deferred) on success.
    ///
    /// # Errors
    ///
    /// * Returns an internal or protocol-specific error.
    pub async fn request_deferred_credential(
        &self,
        token: String,
        transaction_id: String,
    ) -> Result<CredentialResponse> {
        let token = serde_json::from_value(serde_json::Value::String(token))
            .map_err(|err| Error::OID4VCIInternal(err.to_string()))?;

        self.0
            .request_deferred_credential(&token, &transaction_id)
            .await
            .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
    }

    /// Perform extra verification of the passed `Credential`.
    ///
    /// # Arguments
    ///
    /// * `credential` - a `Credential` to verify.
    ///
    /// # Returns
    ///
    /// Empty unit.
    pub async fn verify_credential_extra(
        &self,
        credential: &agent_sdk::vc::Credential,
    ) -> Result<()> {
        self.0
            .verify_credential_extra(credential)
            .await
            .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
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
    pub async fn store_credential(
        &self,
        credential: Credential,
        credential_metadata: CredentialMetadata,
    ) -> Result<String> {
        self.0
            .store_credential(&credential, &credential_metadata)
            .await
            .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
    }

    /// Send notification to the Issuer.
    ///
    /// # Arguments
    ///
    /// * `token` - an Access Token.
    /// * `notification` - the notification details.
    pub async fn send_notification(&self, token: String, notification: Notification) -> Result<()> {
        let token = serde_json::from_value(serde_json::Value::String(token))
            .map_err(|err| Error::OID4VCIInternal(err.to_string()))?;

        self.0
            .send_notification(&token, notification.into())
            .await
            .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
    }
}

pub type AuthorizationCodeCallback = Box<
    dyn FnOnce(Url) -> Pin<Box<dyn Future<Output = std::result::Result<String, io::Error>> + Send>>
        + Send,
>;
pub type AuthorizationCallback = Box<
    dyn FnOnce(
            agent_sdk::vc::oid4vci::AuthzFlow,
        )
            -> Pin<Box<dyn Future<Output = std::result::Result<String, io::Error>> + Send>>
        + Send,
>;

#[async_trait]
trait _HolderWrapperTrait: Send + Sync {
    fn get_issuer_metadata(&self) -> agent_sdk::vc::oid4vci::IssuerMetadata;

    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: AuthorizationCodeCallback,
    ) -> agent_sdk::vc::oid4vci::Result<agent_sdk::vc::oid4vci::TokenResponse>;

    async fn request_credential(
        &self,
        token: &agent_sdk::vc::oid4vci::AccessToken,
        cred_def_id: &str,
        key_metadata: &[agent_sdk::vc::core::KeyMetadata],
    ) -> agent_sdk::vc::oid4vci::Result<agent_sdk::vc::oid4vci::CredentialResponseResolved>;

    async fn request_deferred_credential(
        &self,
        token: &agent_sdk::vc::oid4vci::AccessToken,
        transaction_id: &str,
    ) -> agent_sdk::vc::oid4vci::Result<agent_sdk::vc::oid4vci::CredentialResponseResolved>;

    async fn verify_credential_extra(
        &self,
        credential: &agent_sdk::vc::Credential,
    ) -> agent_sdk::vc::oid4vci::Result<()>;

    async fn store_credential(
        &self,
        credential: &agent_sdk::vc::Credential,
        credential_metadata: &agent_sdk::vc::CredentialMetadata,
    ) -> agent_sdk::vc::oid4vci::Result<String>;

    async fn get_access_token(
        &self,
        offer_params: &agent_sdk::vc::oid4vci::CredentialOfferParams,
        authorization_callback: AuthorizationCallback,
    ) -> agent_sdk::vc::oid4vci::Result<agent_sdk::vc::oid4vci::TokenResponse>;

    async fn send_notification(
        &self,
        token: &agent_sdk::vc::oid4vci::AccessToken,
        notification: AsdkNotification,
    ) -> agent_sdk::vc::oid4vci::Result<()>;
}

pub struct _HolderWrapper<H: agent_sdk::vc::oid4vci::Holder>(H);

#[async_trait]
impl<H: agent_sdk::vc::oid4vci::Holder> _HolderWrapperTrait for _HolderWrapper<H> {
    fn get_issuer_metadata(&self) -> agent_sdk::vc::oid4vci::IssuerMetadata {
        self.0.get_issuer_metadata()
    }

    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: AuthorizationCodeCallback,
    ) -> agent_sdk::vc::oid4vci::Result<agent_sdk::vc::oid4vci::TokenResponse> {
        self.0
            .authz_code_flow_with_scope(scope, authorization_callback)
            .await
    }

    async fn request_credential(
        &self,
        token: &agent_sdk::vc::oid4vci::AccessToken,
        cred_def_id: &str,
        key_metadata: &[agent_sdk::vc::core::KeyMetadata],
    ) -> agent_sdk::vc::oid4vci::Result<agent_sdk::vc::oid4vci::CredentialResponseResolved> {
        self.0
            .request_credential(token, cred_def_id, key_metadata)
            .await
    }

    async fn request_deferred_credential(
        &self,
        token: &agent_sdk::vc::oid4vci::AccessToken,
        transaction_id: &str,
    ) -> agent_sdk::vc::oid4vci::Result<agent_sdk::vc::oid4vci::CredentialResponseResolved> {
        self.0
            .request_deferred_credential(token, transaction_id)
            .await
    }

    async fn verify_credential_extra(
        &self,
        credential: &agent_sdk::vc::Credential,
    ) -> agent_sdk::vc::oid4vci::Result<()> {
        self.0.verify_credential_extra(credential).await
    }

    async fn store_credential(
        &self,
        credential: &agent_sdk::vc::Credential,
        credential_metadata: &agent_sdk::vc::CredentialMetadata,
    ) -> agent_sdk::vc::oid4vci::Result<String> {
        self.0
            .store_credential(credential, credential_metadata)
            .await
    }

    async fn get_access_token(
        &self,
        offer_params: &agent_sdk::vc::oid4vci::CredentialOfferParams,
        authorization_callback: AuthorizationCallback,
    ) -> agent_sdk::vc::oid4vci::Result<agent_sdk::vc::oid4vci::TokenResponse> {
        self.0
            .get_access_token(offer_params, authorization_callback)
            .await
    }

    async fn send_notification(
        &self,
        token: &agent_sdk::vc::oid4vci::AccessToken,
        notification: AsdkNotification,
    ) -> agent_sdk::vc::oid4vci::Result<()> {
        self.0.send_notification(token, notification).await
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct Notification {
    pub notification_id: String,
    pub event: NotificationEvent,
    pub event_description: Option<String>,
}
impl From<Notification> for AsdkNotification {
    fn from(value: Notification) -> Self {
        Self::new(
            value.notification_id,
            value.event.into(),
            value.event_description.clone(),
        )
    }
}
#[derive(uniffi::Enum, Clone, Debug)]
pub enum NotificationEvent {
    CredentialAccepted,
    CredentialFailure,
    CredentialDeleted,
}

impl From<NotificationEvent> for AsdkNotificationEvent {
    fn from(value: NotificationEvent) -> Self {
        match value {
            NotificationEvent::CredentialAccepted => Self::CredentialAccepted,
            NotificationEvent::CredentialFailure => Self::CredentialFailure,
            NotificationEvent::CredentialDeleted => Self::CredentialDeleted,
        }
    }
}
