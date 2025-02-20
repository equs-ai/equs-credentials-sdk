use crate::nonce::Nonce;
use crate::vault::CredentialEntry;
use crate::vc::claims::Claims;
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp::{InternalError, ProtocolError};
use crate::vc::presentation_exchange::{PresentationDefinition, PresentationSubmission};

use async_trait::async_trait;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{IntoError, Snafu};
use std::collections::HashMap;
use std::fmt::Debug;
use url::Url;

pub type CredentialsMapping = HashMap<String, Vec<CredentialEntry>>;
pub type CredentialMapping = HashMap<String, CredentialEntry>;
pub type ClientMetadata = openid4vp::core::authorization_request::parameters::ClientMetadata;
pub type WalletMetadata = openid4vp::core::metadata::WalletMetadata;
pub type ResponseType = openid4vp::core::authorization_request::parameters::ResponseType;
pub type ResponseMode = openid4vp::core::authorization_request::parameters::ResponseMode;

/// Metadata for an ID Token.
///
/// - `id_token_key`: metadata for the key used to sign the SIOP ID token.
/// - `lifetime`: lifetime of the ID token.
#[derive(Debug)]
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
#[derive(Debug, Default)]
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

/// A session with state managed during the presentation.
///
/// Contains [Nonce, PresentationDefinition].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSession {
    pub nonce: Nonce,
    pub presentation_definition: PresentationDefinition,
    pub auth_request_jwt: Option<String>,
}

/// A resolved `OID4VP` authorization request.
///
/// `client_id` Verifier's identifier.
/// `presentation_definition` Rules for the required Verifiable Presentation(s).
/// `nonce` Unique value to prevent replay attacks.
/// `response_mode` Method for returning the authorization response.
/// `response_uri` URI to send the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAuthRequest {
    pub client_id: String,
    pub client_metadata: ClientMetadata,
    pub presentation_definition: PresentationDefinition,
    pub nonce: Nonce,
    pub response_type: ResponseType,
    pub response_mode: ResponseMode,
    pub response_uri: Url,
    pub state: Option<String>,
}

/// An `OID4VP` response configuration of authorization request object.
#[derive(Debug, Clone)]
pub struct AuthResponseOptions {
    pub type_: ResponseType,
    pub mode: ResponseMode,
    pub submission_uri: Url,
    pub state: Option<String>,
}

/// An OID4VP authorization response.
///
/// `vp_token` VP Token containing the Verifiable Presentation(s).
/// `presentation_submission` Details of the submitted presentation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationResponse {
    pub vp_token: serde_json::Value,
    pub presentation_submission: PresentationSubmission,
    pub id_token: Option<String>,
    pub state: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PassAuthRequestObject {
    ByValue,
    ByReference(Url),
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
pub trait Holder: Send + Sync {
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
    /// A redirect URL if the presentation is successful, or `None` on success without redirection.
    ///
    /// # Errors
    ///
    /// * [InternalError::PresentationExchange] - if there is an issue with parsing the presentation metadata.
    /// * [InternalError::VC] - if a required credential is not found.
    /// * [InternalError::AuthorizationResponse] - if the submission of the authorization response fails.
    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>, Error>;

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
    /// A redirect URL if the presentation is successful, or `None` on success without redirection.
    ///
    /// # Errors
    ///
    /// * [InternalError::PresentationExchange] - If there is an issue with parsing the presentation metadata.
    /// * [InternalError::Parse] - if there is an issue with parsing the generated authorization response.
    /// * [InternalError::AuthorizationResponse] - if the submission of the authorization response fails.
    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        credential_mapping: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>, Error>;

    /// Decline the authorization request by sending authorization error response to the `response_uri` endpoint.
    ///
    /// # Arguments
    ///
    /// * `auth_request` - the resolved authorization request.
    ///
    /// # Errors
    ///
    /// * [InternalError::HttpClient] - if the submission of the authorization error response fails.
    async fn decline_authorization_request(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<(), Error>;
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
pub trait Verifier: Send + Sync {
    /// Creates an `OID4VP` authorization request.
    ///
    /// # Arguments
    ///
    /// * `presentation_definition` - the presentation definition specifying the presentation requirements.
    /// * `pass_auth_request_object` - how to pass an authorization request object to holder, by value or by reference.
    /// * `auth_response_options` - config about how and where to send authorization response.
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
        presentation_definition: &PresentationDefinition,
        auth_response_options: &AuthResponseOptions,
        pass_auth_request_object: &PassAuthRequestObject,
        wallet_metadata: Option<&WalletMetadata>,
    ) -> Result<(Url, PresentationSession), Error>;

    /// Verifies the presentation provided by the Holder.
    ///
    /// # Arguments
    ///
    /// * `authorization_response` - the authorization response containing the VP token and presentation submission.
    /// * `session` - a session object containing `Nonce` and `PresentationDefinition`,
    ///  which are generated when the `create_authorization_request` method is called.
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
    ) -> Result<Claims, Error>;
}

use crate::vc::oid4vp::internal_error::Oid4VpLibSnafu;
use openid4vp::core::error::Error as SpruceErr;

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
