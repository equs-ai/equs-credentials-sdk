use crate::nonce::Nonce;
use crate::utils::wasm::{WasmNotSend, WasmNotSync};
use crate::vault::CredentialEntry;
use crate::vc::claims::Claims;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp::internal_error::Oid4VpLibSnafu;
use crate::vc::oid4vp::{ErrorType, InternalError, ProtocolError};
use crate::vc::presentation_exchange::PresentationSubmission;
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use common_macros::DebugError;
use openid4vp::core::error::Error as SpruceErr;
use serde::{Deserialize, Serialize};
use snafu::{IntoError, Snafu};
use std::collections::HashMap;
use std::fmt::Debug;

pub const VP_TOKEN: &str = "vp_token";
pub const ID_TOKEN: &str = "id_token";
pub const STATE: &str = "state";
pub const PRESENTATION_SUBMISSION: &str = "presentation_submission";
pub const TRANSACTION_DATA_HASHES: &str = "transaction_data_hashes";
pub const TRANSACTION_DATA_HASHES_ALG: &str = "transaction_data_hashes_alg";

pub type CredentialMapping = HashMap<String, Vec<CredentialEntry>>;
pub type CredentialsMapping = HashMap<String, CredentialsFindResult>;

pub type TransactionDataResponse = openid4vp::core::response::TransactionDataResponse;
#[derive(Debug, Serialize, Deserialize)]
pub enum CredentialsFindResult {
    Credentials(Vec<CredentialEntry>),
    Reason(FindVCsFailReason),
}

pub type ClaimPath = Vec<String>;

#[derive(Debug, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub enum FindVCsFailReason {
    Paths(Vec<ClaimPath>),
    TypesNotMatched,
    CredentialsNotFound,
}

pub type ClientMetadata = openid4vp::core::authorization_request::parameters::ClientMetadata;
pub type WalletMetadata = openid4vp::core::metadata::WalletMetadata;
pub type ResponseType = openid4vp::core::authorization_request::parameters::ResponseType;
pub type ResponseMode = openid4vp::core::authorization_request::parameters::ResponseMode;
pub type ClientIdPrefix = openid4vp::core::authorization_request::parameters::ClientIdPrefix;
pub type ClientId = openid4vp::core::authorization_request::parameters::ClientId;

pub type ResolvedPresentationQuery =
    openid4vp::core::authorization_request::ResolvedPresentationQuery;
pub type Url = url::Url;

pub type HttpMethodForAuth = openid4vp::core::authorization_request::parameters::HttpMethodForAuth;

pub type TransactionDataItem =
    openid4vp::core::authorization_request::parameters::TransactionDataItem;

pub type HashAlgorithm = openid4vp::core::authorization_request::parameters::HashAlgorithm;
pub type ExpectedOrigins = openid4vp::core::authorization_request::parameters::ExpectedOrigins;

use crate::utils::b64::get_hash_and_base64;
use crate::vc::oid4vp::Error::Protocol;
pub use openid4vp::core::response::parameters::TransactionDataHashes;
pub use openid4vp::core::response::parameters::TransactionDataHashesAlg;

/// Metadata for an ID Token.
///
/// - `id_token_key`: metadata for the key used to sign the SIOP ID token.
/// - `lifetime`: lifetime of the ID token.
#[derive(Debug, Serialize, Deserialize)]
#[serde[rename_all = "camelCase"]]
pub struct IdTokenMetadata {
    pub key_metadata: KeyMetadata,
    pub lifetime: time::Duration,
}

/// Metadata for an Authorization Response.
///
/// # Fields
///
/// - `claims_to_exclude` - map of claims divided by input descriptors that need to be excluded.
/// - `id_token_metadata`: metadata containing the signing key and lifetime for the SIOP ID token
///
/// Exclude works for optional claims only. Excluding non-optional claims will throw a
///     [crate::vc::presentation_exchange::Error::InvalidClaimsToExclude]
/// ```
/// use std::collections::HashMap;
/// let mut map = HashMap::new();
/// map.insert("Identity-1", vec!["$.name".to_string()]);
/// ```
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationResponseMetadata {
    pub claims_to_exclude: Option<HashMap<String, Vec<String>>>,
    pub id_token_metadata: Option<IdTokenMetadata>,
}

impl AuthorizationResponseMetadata {
    pub fn with_excluded_claims(claims: HashMap<String, Vec<String>>) -> Self {
        Self {
            claims_to_exclude: Some(claims),
            id_token_metadata: None,
        }
    }

    pub fn add_claims_to_exclude(&mut self, descriptor_id: String, claim: String) -> &mut Self {
        let claims_to_exclude = self.claims_to_exclude.get_or_insert(HashMap::new());

        if let Some(claims) = claims_to_exclude.get_mut(&descriptor_id) {
            claims.push(claim);
        } else {
            claims_to_exclude.insert(descriptor_id, vec![claim]);
        }

        self
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequestMetadata {
    pub auth_response_options: AuthResponseOptions,
    pub pass_auth_request_object: PassAuthRequestObject,
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-2.8.1
    pub transaction_data: Option<Vec<TransactionDataItem>>,
    pub expected_origins: Option<ExpectedOrigins>,
}

/// A session with state managed during the presentation.
///
/// Contains [Nonce, ResolvedPresentationQuery].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSession {
    pub nonce: Nonce,
    pub resolved_presentation_query: ResolvedPresentationQuery,
    pub auth_request_jwt: Option<String>,
}

/// Result of the presenting credentials.
///
/// # Variants
///
/// * [PresentationResult::AuthorizationResponse] - [AuthorizationResponse] when Digital Credentials API response mode is used (`response_mode: dc_api` or `response_mode: dc_api.jwt`)
/// * [PresentationResult::RedirectUri] - Redirect URI, which is got, either:
///     * Can be returned from Verifier for Authorization Response.
///     * In the case of Same Device Flow, Authorization Response is embedded into the redirect URI as a fragment.
/// * [PresentationResult::Presented] - Presentation is successfully presented to the Verifier
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PresentationResult {
    AuthorizationResponse(AuthorizationResponse),
    RedirectUri(Url),
    Presented,
}

/// A resolved `OID4VP` authorization request.
///
/// `client_id` Verifier's identifier. `client_id` has format of `client_id_prefix`:`client_id`.
/// `client_metadata` - A JSON object containing the Verifier metadata values
/// `presentation_definition` Rules for the required Verifiable Presentation(s).
/// `nonce` Unique value to prevent replay attacks.
/// `response_type` - defines how the Authorization Response constructed.
/// `response_mode` Method for returning the authorization response.
/// `response_uri` URI to send the response.
/// `state` - may be used by a verifier to link requests and responses
/// `transaction_data` - Array of strings, where each string is a base64url encoded JSON object that contains a typed parameter set with details about the transaction that the Verifier is requesting the End-User to authorize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolvedAuthRequest {
    pub client_id: ClientId,
    pub client_metadata: ClientMetadata,
    #[serde(flatten)]
    pub resolved_presentation_query: ResolvedPresentationQuery,
    pub nonce: Nonce,
    pub response_type: ResponseType,
    pub response_mode: ResponseMode,
    pub response_uri: Option<Url>,
    pub state: Option<String>,
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-2.8.1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<TransactionDataItem>>,
}

/// An `OID4VP` response configuration of authorization request object.
#[derive(Debug, Clone)]
pub struct AuthResponseOptions {
    pub type_: ResponseType,
    pub mode: ResponseMode,
    pub submission_uri: Option<Url>,
    pub state: Option<String>,
}

/// An OID4VP authorization response.
///
/// `vp_token` VP Token containing the Verifiable Presentation(s).
/// `presentation_submission` Details of the submitted presentation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationResponseObject {
    pub vp_token: serde_json::Value,
    pub presentation_submission: Option<PresentationSubmission>,
    pub id_token: Option<String>,
    pub state: Option<String>,
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.3.1-2.2.1
    #[serde(flatten)]
    pub transaction_data_response: Option<TransactionDataResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum AuthorizationResponse {
    Plain(AuthorizationResponseObject),
    Jwe(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct CredentialVerificationMetadata {
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-2.8.1
    pub transaction_data: Option<Vec<TransactionDataItem>>,
    // In the case of DC API response mode, the following field is used as audience to verify the signature of the VP Token.
    pub audience: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PassAuthRequestObject {
    ByValue,
    ByReference {
        uri: Url,
        method: Option<HttpMethodForAuth>,
    },
}

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(transparent)]
    Internal { source: InternalError },
    #[snafu(transparent)]
    Protocol { source: ProtocolError },
}

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
///
/// # Implementation
///
/// Use [HolderBuilder](crate::vc::oid4vp::HolderBuilder) to instantiate a service.
/// Existing implementation of the API is not exposed.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Holder: WasmNotSend + WasmNotSync {
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
    /// *NOTE:* In case of Same Device Flow, `redirect_uri` field of `Error` must contain URL where
    /// authorization error response is embedded as a fragment.
    ///
    /// * [ProtocolError] - if the validation of authorization request fails
    /// * [InternalError::UrlParse] - if the request URI is invalid
    /// * [InternalError::Oid4VpLib] - if the resolution of the authorization request fails.
    async fn get_authorization_request(
        &self,
        request_uri: &Url,
    ) -> Result<ResolvedAuthRequest, Error>;

    /// Automatically presents credentials to the Verifier based on the authorization request.
    ///
    /// This method selects the first appropriate credential that matches the requirements of the authorization request.
    /// To present specific credentials, use [Holder::find_vcs_for_presentation] to discover suitable credentials and
    /// [Holder::present_credentials] to manually present them.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request containing the presentation requirements.
    /// * `metadata` - the metadata for the authorization response.
    ///
    /// # Returns
    ///
    /// * [PresentationResult] - The result of presenting credentials, which can be either:
    ///   * [PresentationResult::AuthorizationResponse] - [AuthorizationResponse] when Digital Credentials API response mode is used (`response_mode: dc_api` or `response_mode: dc_api.jwt`)
    ///   * [PresentationResult::RedirectUri] - Redirect URI, which is got, either:
    ///     * Can be returned from Verifier for Authorization Response.
    ///     * In the case of Same Device Flow, Authorization Response is embedded into the redirect URI as a fragment.
    ///   * [PresentationResult::Presented] - Presentation is successfully presented to the Verifier
    ///
    /// # Errors
    ///
    /// *NOTE:* In case of Same Device Flow, `redirect_uri` field of `Error` must contain URL where
    /// authorization error response is embedded as a fragment.
    ///
    /// * [InternalError::PresentationExchange] - if there is an issue with parsing the presentation metadata.
    /// * [InternalError::VC] - if a required credential is not found.
    /// * [InternalError::AuthorizationResponse] - if the submission of the authorization response fails.
    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<PresentationResult, Error>;

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
    /// *NOTE:* In case of Same Device Flow, `redirect_uri` field of `Error` must contain URL where
    /// authorization error response is embedded as a fragment.
    ///
    /// * [InternalError::PresentationExchange] - If there is an issue with parsing the presentation metadata.
    /// * [InternalError::VC] - If an error occurs in the `vc::core` during credential search and extraction
    async fn find_vcs_for_presentation(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<CredentialsMapping, Error>;

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
    /// * [PresentationResult] - The result of presenting credentials, which can be either:
    ///   * [PresentationResult::AuthorizationResponse] - [AuthorizationResponse] when Digital Credentials API response mode is used (`response_mode: dc_api` or `response_mode: dc_api.jwt`)
    ///   * [PresentationResult::RedirectUri] - Redirect URI, which is got, either:
    ///     * Can be returned from Verifier for Authorization Response.
    ///     * In the case of Same Device Flow, Authorization Response is embedded into the redirect URI as a fragment.
    ///   * [PresentationResult::Presented] - Presentation is successfully presented to the Verifier
    ///
    /// # Errors
    ///
    /// *NOTE:* In case of Same Device Flow, `redirect_uri` field of `Error` must contain URL where
    /// authorization error response is embedded as a fragment.
    ///
    /// * [InternalError::PresentationExchange] - If there is an issue with parsing the presentation metadata.
    /// * [InternalError::Parse] - if there is an issue with parsing the generated authorization response.
    /// * [InternalError::AuthorizationResponse] - if the submission of the authorization response fails.
    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        credential_mapping: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<PresentationResult, Error>;

    /// Decline the authorization request by sending authorization error response to the `response_uri` endpoint.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request.
    /// # Returns
    ///
    /// An optional redirect URL(in case of Same Device Flow) where the error response is embedded as a fragment.
    ///
    /// # Errors
    ///
    /// * [InternalError::HttpClient] - if the submission of the authorization error response fails.
    async fn decline_authorization_request(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<Option<Url>, Error>;
}

/// The `OID4VP` `Verifier` API.
///
/// Supports presentation request and verification flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// # Features
///
/// * Create an authorization request.
/// * Verify the presentations.
///
/// # Implementation
///
/// Use [VerifierBuilder](crate::vc::oid4vp::VerifierBuilder) to instantiate a service.
/// Existing implementation of the API is not exposed.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Verifier: WasmNotSend + WasmNotSync {
    /// Creates an `OID4VP` authorization request.
    ///
    /// # Arguments
    ///
    /// * `resolved_presentation_query` - the presentation definition specifying the presentation requirements.
    /// * `auth_request_metadata` - the metadata needed to create the AuthorizationRequest. It itself contains:
    /// `pass_auth_request_object` - how to pass an authorization request object to holder, by value or by reference.
    /// `auth_response_options` - config about how and where to send authorization response.
    /// `transaction_data` - transaction data that the holder should return the hashes of.
    /// `expected_origins` - a list of expected origins when generating a signed AuthorizationRequest for dc_api or dc_api.jwt response mode.
    /// * `wallet_metadata` - optional metadata of holder. if it is `None`, metadata form `metadata::default_metadata()` will be used
    ///
    /// # Returns
    ///
    ///  - `Url` - the OID4VP authorization request url
    ///  - `PresentationSession` - the `session` state that will be used when the `verify_presentation` method is called.
    ///
    /// # Errors
    ///
    /// * [InternalError::Oid4VpLib] - if an error occurs during the creation of the authorization request object.
    /// * [InternalError::KMS] - if there is an error during Issuer key resolution.
    /// * [InternalError::Parse] - if an error occurs during metadata parsing.
    /// * [InternalError::NonceGeneration] - if an error occurs during generation of nonce
    async fn create_authorization_request(
        &self,
        resolved_presentation_query: &ResolvedPresentationQuery,
        auth_request_metadata: &AuthorizationRequestMetadata,
        wallet_metadata: Option<&WalletMetadata>,
    ) -> Result<(Url, PresentationSession), Error>;

    /// Verifies the presentation provided by the Holder.
    ///
    /// # Arguments
    ///
    /// * `authorization_response` - the authorization response containing the VP token and presentation submission.
    /// * `session` - a session object containing `Nonce` and `PresentationDefinition`,
    ///  which are generated when the `create_authorization_request` method is called.
    /// * `verification_metadata` - metadata that contains:
    ///     - `transaction_data` - transaction data that the holder should return the hashes of.
    ///     - `audience` - In the case of DC API response mode, audience is Origin of the Verifier to be used while validating the signature of the VP Token.
    /// # Returns
    ///
    /// * The verified claims as a JSON object on success.
    ///
    /// # Errors
    ///
    /// * [InternalError::AuthorizationResponse] - if an error occurs while parsing or validating the authorization response.
    /// * [InternalError::FormatNotSupported] - if the provided presentation format is not supported.
    /// * [InternalError::VC] - if the presentation verification fails.
    async fn verify_presentation(
        &self,
        authorization_response: &AuthorizationResponse,
        session: &PresentationSession,
        verification_metadata: &CredentialVerificationMetadata,
    ) -> Result<Claims, Error>;
}

impl From<SpruceErr> for Error {
    fn from(value: SpruceErr) -> Self {
        match value {
            SpruceErr::Internal(e) => Self::Internal {
                source: Oid4VpLibSnafu.into_error(e),
            },
            SpruceErr::Protocol(e) => Self::Protocol {
                source: ProtocolError::new(e.r#type, e.description, e.state),
            },
        }
    }
}

pub fn get_transaction_data_hash(
    value: &TransactionDataItem,
    hash_alg: HashAlgorithm,
) -> Result<String, Error> {
    let json_str = serde_json::to_string(value).map_err(|e| {
        let err_msg = format!("Wrong format of transaction data item: {}", e);
        Protocol {
            source: ProtocolError::new(ErrorType::InvalidTransactionData, Some(err_msg), None),
        }
    })?;
    let encoded_json_str = BASE64_URL_SAFE_NO_PAD.encode(&json_str);
    let encoded_expected_hash = get_hash_and_base64(encoded_json_str, hash_alg);
    Ok(encoded_expected_hash)
}
