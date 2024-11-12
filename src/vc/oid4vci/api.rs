use crate::http::HttpError;
use crate::nonce::NonceData;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vci::internal_error::RequestSnafu;
use crate::vc::oid4vci::{metadata, InternalError, ProtocolError};
use crate::vc::{Claims, Credential, CredentialMetadata};
use async_trait::async_trait;
use oauth2::AccessToken;
use oid4vci::core::profiles::CoreProfilesOffer;
use oid4vci::credential::RequestError;
use serde::{Deserialize, Serialize};
use snafu::{IntoError, Snafu};
use std::fmt::Debug;
use tracing::{instrument, Level};

// Data types
pub type IssuerMetadata = metadata::IssuerMetadata;
pub type CredDefMetadata = metadata::CredentialMetadata;
pub type CredDefMetadataProfile = oid4vci::core::profiles::CoreProfilesMetadata;
pub type AuthorizationMetadata = oid4vci::metadata::AuthorizationMetadata;
pub type CredentialOffer = oid4vci::credential_offer::CredentialOffer<CoreProfilesOffer>;
pub type CredentialOfferGrants = oid4vci::credential_offer::CredentialOfferGrants;
pub type CredentialOfferParams =
    oid4vci::credential_offer::CredentialOfferParameters<CoreProfilesOffer>;
pub type CredentialRequest = oid4vci::core::credential::Request;
pub type CredentialResponse = oid4vci::core::credential::Response;
pub type TokenResponse = oid4vci::token::Response;
pub type AuthorizationCodeGrant = oid4vci::credential_offer::AuthorizationCodeGrant;
pub type ErrorType = oid4vci::credential::ErrorType;

/// A result of the Credential issuance handled by `Holder`
///
/// Enum value `Credential` contains issued [Credential].
///
/// *NOTE*: `deferred` flow and `notifications` currently are not supported.
#[derive(Debug, Clone)]
pub enum CredentialResult {
    Deferred {
        transaction_id: String,
    },
    Credential {
        credential: Credential,
        notification_id: Option<String>,
    },
}

/// A resolved response of the Credential issuance handled by `Holder`
///
/// `data` contains `CredentialResult`.
/// `nonce_data` contains optional `NonceData` for subsequent calls.
#[derive(Debug, Clone)]
pub struct CredentialResponseResolved {
    pub data: CredentialResult,
    pub nonce_data: Option<NonceData>,
}

/// A session with state managed during the issuance.
///
/// Contains [NonceData].
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IssuanceSession {
    pub nonce: Option<NonceData>,
    pub notification_id: Option<String>,
    pub transaction_id: Option<String>,
}

/// `oid4vci` API common error.
///
/// Used by `oid4vci` `Issuer` and `Holder`.
///
/// * [Error::Protocol] encapsulates all expected [ProtocolError] errors specific to the standard.
///   See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// * [Error::Internal] error contains all unexpected errors.
#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(transparent)]
    Internal { source: InternalError },
    #[snafu(transparent)]
    Protocol { source: ProtocolError },
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Internal { source } => {
                write!(fmt, "{:#?}", source)?;
            }
            Self::Protocol { source } => {
                write!(fmt, "{:#?}", source)?;
            }
        }

        Ok(())
    }
}

/// `Result` alias for `oid4vci`-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// An async `oid4vci` `Issuer` API.
///
/// Supports issuance flow according to the `oid4vci` standard.
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>.
///
/// # Supported features
///
/// * exposing metadata
/// * credential issuance (immediate)
/// * credential offer generation
///
/// # Implementation
///
/// Use [IssuerBuilder](crate::vc::oid4vci::IssuerBuilder) to instantiate a service.
/// Existing implementation of the API is not exposed.
#[async_trait]
pub trait Issuer: Send + Sync {
    /// Returns the `Metadata` of the `Issuer`.
    ///
    /// # Returns
    ///
    /// An `IssuerMetadata`.
    fn get_issuer_metadata(&self) -> IssuerMetadata;

    /// Returns the `CredDefMetadata` for the provided `CredentialRequest`.
    ///
    /// # Returns
    ///
    /// `Some(CredDefMetadata)` if `cred_request` contains valid values.
    /// `None` otherwise
    fn get_cred_def_metadata(&self, cred_request: &CredentialRequest) -> Option<CredDefMetadata>;

    /// Create a `CredentialOffer` for multiple `CredDef` ids.
    ///
    /// Generated `CredentialOffer` matches provided `CredentialDefinition`s
    /// and should be later used by `Holder` to create a corresponding `CredentialRequest`.
    ///
    /// # Arguments
    ///
    /// * `cred_def_ids` - a vector with `CredentialDefinition` IDs.
    /// * `grants` - grant types of the generated `Offer`, contains which flow is defined - pre-authorized/authorized.
    ///
    /// # Returns
    ///
    /// A `CredentialOfferParams` and the corresponding Url to be shared with `Holder` on success.
    ///
    /// # Errors
    ///
    /// * [Error::Protocol] - expected protocol-specific error.
    ///     * [ErrorType::InvalidRequest]
    ///     * [ErrorType::UnsupportedCredentialType]
    /// * [InternalError::Parse] - fails to parse the payload.
    /// * [InternalError::UrlParse] - fails to parse `Url`.
    fn create_credential_offer(
        &self,
        cred_def_ids: Vec<&str>,
        grants: &CredentialOfferGrants, // grant type (auth code, pre-auth code), etc.
    ) -> Result<(CredentialOfferParams, url::Url)>;

    /// Issue a `Credential` based on the provided `CredentialRequest`.
    ///
    /// `CredentialRequest` should match some existing `CredentialDefinition` defined in the `IssuerMetadata`.
    /// `Proof of Possession` is mandatory.
    ///
    /// This method should be used for `Immediate` credential issuance.
    /// `Deferred` option is not supported yet.
    ///
    /// # Arguments
    ///
    /// * `cred_request` - a `CredentialRequest` used for `Credential` generation.
    /// * `token` - an access token used for authorization.
    /// * `claims` - claims to include into the `Credential`.
    /// * `session` - a `&mut` session object which contains `Nonce` and other state.
    /// Will be updated if the state was changed.
    ///
    /// # Returns
    ///
    /// A `CredentialResponse` (containing serialized `Credential`) on success.
    ///
    /// # Errors
    ///
    /// * [Error::Protocol] - expected protocol-specific error.
    ///     * [ErrorType::InvalidRequest]
    ///     * [ErrorType::InvalidProof]
    ///     * [ErrorType::InvalidToken]
    ///     * [ErrorType::UnsupportedCredentialType]
    ///     * [ErrorType::UnsupportedCredentialFormat]
    /// * [InternalError::VC] - `vc::core` error during `Credential` signing or `Proof` validation.
    async fn issue_credential(
        &self,
        cred_request: &CredentialRequest,
        token: &str,
        claims: &Claims,
        session: &mut IssuanceSession,
    ) -> Result<CredentialResponse>;
}

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
///
/// *NOTE*: Pre-authorized code flow is not yet supported.
///
/// # Implementation
///
/// Use [HolderBuilder](crate::vc::oid4vci::HolderBuilder) to instantiate a service.
/// Existing implementation of the API is not exposed.
#[async_trait]
pub trait Holder: Send + Sync {
    /// Returns the `Metadata` of the `Issuer`.
    ///
    /// # Returns
    ///
    /// An `IssuerMetadata`.
    fn get_issuer_metadata(&self) -> IssuerMetadata;

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
    /// * [Error::Protocol] - expected protocol-specific error.
    ///     * [ErrorType::InvalidRequest]
    /// * [InternalError::Request] - fails to make a call to the `Issuer`.
    async fn authz_code_flow_with_scope(
        &self,
        scope: String,
        authorization_callback: impl FnOnce(url::Url) -> String + Send,
    ) -> Result<TokenResponse>;

    /// Run Pre-authorized Code Flow to authorize the `Holder`.
    ///
    /// *NOTE*: **not implemented yet**.
    ///
    /// # Arguments
    ///
    /// * `pre_authorized_code` - a pre-authorization code.
    /// * `tx_code` - a transaction code.
    /// * `cred_def_id` - a `CredentialDefinition` ID.
    ///
    /// # Returns
    ///
    /// A `TokenResponse` with a valid token to be used for issuing a `Credential` on success.
    async fn pre_authz_code_flow(
        &self,
        pre_authorized_code: String,
        tx_code: String,
        cred_def_id: Option<String>,
    ) -> Result<TokenResponse>;

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
    /// * `nonce` - an optional nonce. If not set `Holder` will re-request nonce from the `Issuer` automatically.
    /// * `key_metadata` - a `KeyMetadata` for corresponding key to be used for signing operations.
    ///
    /// # Returns
    ///
    /// A `CredentialResponseResolved` (Immediate or Deferred) on success.
    /// Optionally includes `NonceData` for the next requests.
    ///
    /// # Errors
    ///
    /// * [Error::Protocol] - expected protocol-specific error.
    ///     * [ErrorType::InvalidRequest]
    ///     * [ErrorType::UnsupportedCredentialType]
    ///     * [ErrorType::UnsupportedCredentialFormat]
    /// * [InternalError::Parse] - fails to parse the payload.
    /// * [InternalError::Request] - fails to make a call to the `Issuer`.
    /// * [InternalError::VC] - `vc::core` error during `Proof` generation or credential signature verification.
    async fn request_credential(
        &self,
        token: &AccessToken,
        cred_def_id: &str,
        nonce: Option<&NonceData>,
        key_metadata: &KeyMetadata,
    ) -> Result<CredentialResponseResolved>;

    /// Store a `Credential`.
    ///
    /// This method will store the `credential` into the `Vault` under the hood.
    ///
    /// # Arguments
    ///
    /// * `credential` - a `Credential` to save.
    /// * `credential_metadata` - the corresponding `CredentialMetadata`.
    ///
    /// # Errors
    ///
    /// * [InternalError::Vault] - error with [Vault](crate::vault::Vault).
    async fn store_credential(
        &self,
        credential: &Credential,
        credential_metadata: &CredentialMetadata,
    ) -> Result<()>;
}

impl From<RequestError<HttpError>> for Error {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn from(value: RequestError<HttpError>) -> Self {
        match &value {
            RequestError::Response(_, body, _) => {
                let result = serde_json::from_slice::<ProtocolError>(body.as_slice());
                match result {
                    Ok(value) => Self::Protocol { source: value },
                    Err(_) => Self::Internal {
                        source: RequestSnafu.into_error(value),
                    },
                }
            }
            _ => Self::Internal {
                source: RequestSnafu.into_error(value),
            },
        }
    }
}
