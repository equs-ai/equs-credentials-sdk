use crate::vault::CredentialEntry;
use crate::vc::oid4vp::InternalError;
use crate::vc::Claims;
use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::ResponseMode;
use oid4vp::core::authorization_request::RequestIndirection;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::collections::HashMap;
use std::fmt::Debug;
use url::Url;

// Data type
pub struct AuthorizationResponseMetadata {}
pub type CredentialMapping = HashMap<String, Vec<CredentialEntry>>;
pub type PresentationSubmission = oid4vp::presentation_exchange::PresentationSubmission;
pub type PresentationDefinition = oid4vp::presentation_exchange::PresentationDefinition;
pub type ClientMetadata = oid4vp::core::authorization_request::parameters::ClientMetadata;
pub type WalletMetadata = oid4vp::core::metadata::WalletMetadata;
pub type Nonce = oid4vp::core::authorization_request::parameters::Nonce;

/// A session with state managed during the presentation.
///
/// Contains [Nonce, PresentationDefinition].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSession {
    pub nonce: Nonce,
    pub presentation_definition: PresentationDefinition,
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
    pub presentation_definition: PresentationDefinition,
    pub nonce: Nonce,
    pub response_mode: ResponseMode,
    pub response_uri: Url,
}

/// An `OID4VP` authorization request.
///
/// It can be represented as a URL using the [auth_request_as_url] helper function.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub client_id: String,
    /// JWT containing Authorization Request parameters.
    pub request_object_jwt: String,
    pub authorization_endpoint: Url,
}

/// An OID4VP authorization response.
///
/// `vp_token` VP Token containing the Verifiable Presentation(s).
/// `presentation_submission` Details of the submitted presentation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationResponse {
    pub vp_token: serde_json::Value,
    pub presentation_submission: PresentationSubmission,
}

#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(transparent)]
    Internal { source: InternalError },
    //TODO: Add Protocol Error
}

impl Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        Ok(())
    }
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
#[async_trait]
pub trait Holder: Send + Sync {
    /// Fetches the `OID4VP` authorization request object from the provided URI.
    ///
    /// # Arguments
    ///
    /// * `auth_req_uri` - a request URI provided by the authorization URL.
    ///
    /// # Returns
    ///
    /// A `ResolvedAuthRequest` with the presentation definition and other relevant details on success.
    ///
    /// # Errors
    ///
    /// * [InternalError::UrlParse] - if the request URI is invalid
    /// * [InternalError::AuthorizationRequest] - if the resolution of the authorization request fails.
    async fn get_authorization_request(
        &self,
        auth_req_uri: &str,
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
    ) -> Result<CredentialMapping, Error>;

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
    /// * [InternalError::Parse] - ff there is an issue with parsing the generated authorization response.
    /// * [InternalError::AuthorizationResponse] - if the submission of the authorization response fails.
    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        credential_mapping: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
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
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Creates an `OID4VP` authorization request.
    ///
    /// # Arguments
    ///
    /// * `presentation_definition` - the presentation definition specifying the presentation requirements.
    /// * `nonce` - a string used to prevent replay attacks, representing the nonce for the request.
    /// * `response_uri` - the URL where the Holder will send the response.
    ///
    /// # Returns
    ///
    ///  - `AuthorizationRequest` - the OID4VP authorization request
    ///  - `PresentationSession` - the `session` state that will be used when the `verify_presentation` method is called.
    ///
    /// # Errors
    ///
    /// * [InternalError::VerifierSession] - if an error occurs during the creation of the verifier session.
    /// * [InternalError::KMS] - if there is an error during Issuer key resolution.
    /// * [InternalError::Parse] - if an error occurs during metadata parsing.
    async fn create_authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &Nonce,
        response_uri: Url,
    ) -> Result<(AuthorizationRequest, PresentationSession), Error>;

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

/// The types of authorization URLs.
///
/// It can be either a request URI from which to retrieve the request object, or the encrypted request object itself.
pub enum AuthorizationUrlType {
    Reference(Url),
    Value,
}

/// Converts an `AuthorizationRequest` into a URL.
///
/// # Arguments
///
/// * `req` - the authorization request.
/// * `type_` - type of authorization URL (by reference or by value).
///
/// # Returns
///
/// * An authorization request URL.
pub fn auth_request_as_url(req: &AuthorizationRequest, type_: AuthorizationUrlType) -> Url {
    let request_indirection = match type_ {
        AuthorizationUrlType::Value => RequestIndirection::ByValue(req.request_object_jwt.clone()),
        AuthorizationUrlType::Reference(at) => RequestIndirection::ByReference(at),
    };
    use oid4vp::core::authorization_request::AuthorizationRequest as SpruceAuthorizationRequest;

    SpruceAuthorizationRequest {
        client_id: req.client_id.clone(),
        request_indirection,
    }
    .to_url(req.authorization_endpoint.clone())
    .unwrap()
}
