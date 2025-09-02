use crate::error::IntoNapiError;
use crate::utils::{from_json_object, parse_url_arg, to_json_object};
use crate::vc::JsonObject;
use agent_sdk::vc::oid4vp::{
    AuthResponseOptions, AuthorizationResponse, AuthorizationResponseObject, HttpMethodForAuth,
    PassAuthRequestObject, PresentationSession as RustPresentationSession, Verifier,
    WalletMetadata,
};
use agent_sdk::vc::presentation_exchange::PresentationSubmission;
use napi::{Error, Result};
use napi_derive::napi;
use url::Url;

/// The `OID4VP` `Verifier` API.
/// This verifier api is used as the inner api the main wrapper in Node.js implementation
/// Supports presentation request and verification flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// @property createAuthorizationRequest - {@link OID4VPVerifier.createAuthorizationRequest}
/// @property verifyPresentation - {@link OID4VPVerifier.verifyPresentation}
#[napi]
pub struct InternalOID4VPVerifier(Box<dyn Verifier>);

impl InternalOID4VPVerifier {
    pub fn from_verifier<V: Verifier + 'static>(verifier: V) -> InternalOID4VPVerifier {
        InternalOID4VPVerifier(Box::new(verifier))
    }
}

#[napi]
impl InternalOID4VPVerifier {
    /// Creates an `OID4VP` authorization request.
    ///
    /// @param {ResolvedPresentationQuery} resolved_presentation_query - the presentation definition specifying the presentation requirements.
    /// @param {AuthResponseOptions} passAuthRequestObject - how to pass an authorization request object to holder, by value or by reference.
    /// @param {PassAuthRequestObject} authResponseOptions - config about how and where to send authorization response.
    /// @param {WalletMetadata | null} [walletMetadata] - optional metadata of holder. if it is `null`, default metadata will be used
    ///
    /// @returns {AuthorizationRequestWithSession}
    #[napi]
    pub async fn create_authorization_request(
        &self,
        #[napi(ts_arg_type = "ResolvedPresentationQuery")] resolved_presentation_query: JsonObject,
        auth_response_options: JsAuthResponseOptions,
        pass_auth_request_object: &JsPassAuthRequestObject,
        #[napi(ts_arg_type = "WalletMetadata | undefined | null")] wallet_metadata: Option<
            JsonObject,
        >,
    ) -> Result<AuthorizationRequestWithSession> {
        let wallet_metadata: Option<WalletMetadata> = if let Some(metadata) = wallet_metadata {
            Some(from_json_object(metadata)?)
        } else {
            None
        };

        let (aut_req_obj_uri, session) = self
            .0
            .create_authorization_request(
                &from_json_object(resolved_presentation_query)?,
                &auth_response_options.try_into()?,
                &pass_auth_request_object.0,
                wallet_metadata.as_ref(),
            )
            .await
            .map_err(IntoNapiError::into_napi_error)?;

        Ok(AuthorizationRequestWithSession {
            authorization_request_uri: aut_req_obj_uri.into(),
            authorization_request_jwt: session.auth_request_jwt.clone(),
            session: session.try_into()?,
        })
    }

    /// Verifies the presentation provided by the Holder.
    ///
    /// @param {AuthorizationResponse} authorizationResponse - the authorization response containing the VP token and presentation submission.
    /// @param {_PresentationSession} session - a session object containing `Nonce` and {@link ResolvedPresentationQuery}, which are generated when the {@link OID4VPVerifier.createAuthorizationRequest} method is called.
    ///
    /// @returns {Claims} - The verified claims as a JSON object on success.
    #[napi(ts_return_type = "Promise<Claims>")]
    pub async fn verify_presentation(
        &self,
        authorization_response: JsAuthorizationResponse,
        session: JsPresentationSession,
    ) -> Result<JsonObject> {
        self.0
            .verify_presentation(&authorization_response.try_into()?, &session.try_into()?)
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(to_json_object)
    }
}

/// An `OID4VP` response configuration of authorization request object.
#[napi(js_name = "AuthResponseOptions", object)]
pub struct JsAuthResponseOptions {
    pub type_: String,
    pub mode: String,
    pub submission_uri: String,
    pub state: Option<String>,
}

impl TryFrom<JsAuthResponseOptions> for AuthResponseOptions {
    type Error = Error;

    fn try_from(value: JsAuthResponseOptions) -> Result<Self> {
        Ok(Self {
            type_: value.type_.into(),
            mode: value.mode.into(),
            submission_uri: Url::parse(&value.submission_uri)
                .map_err(|e| Error::from_reason(e.to_string()))?,
            state: value.state,
        })
    }
}

#[derive(Clone)]
#[napi(js_name = "PassAuthRequestObject")]
pub struct JsPassAuthRequestObject(PassAuthRequestObject);

/// A session with state managed during the presentation.
///
/// @property {string} nonce
/// @property {ResolvedPresentationQuery} resolved_presentation_query
/// @property {string | null} [authorizationRequestJwt]
#[napi(object, js_name = "_PresentationSession")]
pub struct JsPresentationSession {
    pub nonce: String,
    #[napi(ts_type = "ResolvedPresentationQuery")]
    pub resolved_presentation_query: JsonObject,
    pub authorization_request_jwt: Option<String>,
}

#[napi]
impl JsPassAuthRequestObject {
    #[napi(factory)]
    pub fn by_value() -> Self {
        JsPassAuthRequestObject(PassAuthRequestObject::ByValue)
    }

    #[napi(factory)]
    pub fn by_reference(uri: String, method: Option<JsHttpMethodForAuth>) -> Result<Self> {
        let auth_req_obj_uri = parse_url_arg(&uri)?;
        let pass_by_reference = JsPassAuthRequestObject(PassAuthRequestObject::ByReference {
            uri: auth_req_obj_uri,
            method: method.map(|v| v.to_raw()),
        });

        Ok(pass_by_reference)
    }
}

impl TryFrom<RustPresentationSession> for JsPresentationSession {
    type Error = Error;

    fn try_from(value: RustPresentationSession) -> Result<Self> {
        Ok(Self {
            nonce: value.nonce.secret().to_string(),
            resolved_presentation_query: to_json_object(value.resolved_presentation_query)?,
            authorization_request_jwt: value.auth_request_jwt,
        })
    }
}

impl TryFrom<JsPresentationSession> for RustPresentationSession {
    type Error = Error;

    fn try_from(value: JsPresentationSession) -> Result<Self> {
        Ok(Self {
            nonce: serde_json::from_value(serde_json::Value::String(value.nonce))?,
            resolved_presentation_query: from_json_object(value.resolved_presentation_query)?,
            auth_request_jwt: value.authorization_request_jwt,
        })
    }
}

#[napi(object)]
pub struct AuthorizationRequestWithSession {
    pub authorization_request_uri: String,
    pub authorization_request_jwt: Option<String>,
    pub session: JsPresentationSession,
}

/// An OID4VP authorization response.
/// It can be either plain object as below or the Jwe response string of the fields below
/// @property {any} vpToken - VP Token containing the Verifiable Presentation(s).
/// @property {string | null} [idToken] - The OpenID Connect ID token used in the SIOP flow.
/// @property {PresentationSubmission} presentationSubmission - Details of the submitted presentation.
/// @property {string | null} [state] - The state may be used by a verifier to link requests and responses.
#[napi(js_name = "AuthorizationResponseType")]
pub enum JsAuthorizationResponseType {
    Plain,
    Jwe,
}

#[napi(js_name = "AuthorizationResponse", object)]
pub struct JsAuthorizationResponse {
    pub type_: JsAuthorizationResponseType,
    pub object: Option<JsAuthorizationResponseObject>,
    pub jwe: Option<String>,
}

impl TryFrom<JsAuthorizationResponse> for AuthorizationResponse {
    type Error = Error;

    fn try_from(value: JsAuthorizationResponse) -> std::result::Result<Self, Self::Error> {
        match value.type_ {
            JsAuthorizationResponseType::Plain => {
                let object = value.object.ok_or(Error::from_reason(
                    "AuthorizationResponseObject was expected but none",
                ))?;
                Ok(AuthorizationResponse::Plain(object.try_into()?))
            }
            JsAuthorizationResponseType::Jwe => {
                let jwe = value.jwe.ok_or(Error::from_reason(
                    "AuthorizationResponse Jwe was expected but none",
                ))?;
                Ok(AuthorizationResponse::Jwe(jwe))
            }
        }
    }
}

/// An OID4VP authorization response object.
///
/// @property {any} vpToken - VP Token containing the Verifiable Presentation(s).
/// @property {string | null} [idToken] - The OpenID Connect ID token used in the SIOP flow.
/// @property {PresentationSubmission} presentationSubmission - Details of the submitted presentation.
/// @property {string | null} [state] - The state may be used by a verifier to link requests and responses.
#[napi(js_name = "AuthorizationResponseObject", object)]
pub struct JsAuthorizationResponseObject {
    pub vp_token: serde_json::Value,
    pub id_token: Option<String>,
    #[napi(ts_type = "PresentationSubmission")]
    pub presentation_submission: Option<JsonObject>,
    pub state: Option<String>,
}

impl TryFrom<JsAuthorizationResponseObject> for AuthorizationResponseObject {
    type Error = Error;

    fn try_from(value: JsAuthorizationResponseObject) -> Result<Self> {
        let ps: Option<PresentationSubmission> = value
            .presentation_submission
            .map(from_json_object)
            .transpose()?;
        Ok(Self {
            vp_token: value.vp_token,
            id_token: value.id_token,
            presentation_submission: ps,
            state: value.state,
        })
    }
}

#[napi(js_name = "HttpMethodForAuth")]
pub enum JsHttpMethodForAuth {
    GET,
    POST,
}

impl JsHttpMethodForAuth {
    fn to_raw(self) -> HttpMethodForAuth {
        match self {
            JsHttpMethodForAuth::GET => HttpMethodForAuth::GET,
            JsHttpMethodForAuth::POST => HttpMethodForAuth::POST,
        }
    }
}
