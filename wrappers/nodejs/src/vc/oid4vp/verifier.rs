use crate::error::IntoNapiError;
use crate::utils::{from_json_object, parse_url_arg, to_json_object};
use crate::vc::JsonObject;
use crate::vc::oid4vp::JsInnerAuthorizationResponse;
use agent_sdk::vc::dcql::NonEmptyVec;
use agent_sdk::vc::oid4vp::{
    AuthResponseOptions, AuthorizationRequestMetadata, CredentialVerificationMetadata,
    ExpectedOrigins, HttpMethodForAuth, PassAuthRequestObject,
    PresentationSession as RustPresentationSession, Verifier, WalletMetadata,
};
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
        auth_request_metadata: JsAuthorizationRequestMetadata,
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
                &auth_request_metadata.try_into()?,
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
        authorization_response: JsInnerAuthorizationResponse,
        session: JsPresentationSession,
        verification_metadata: JsCredentialVerificationMetadata,
    ) -> Result<JsonObject> {
        self.0
            .verify_presentation(
                &authorization_response.try_into()?,
                &session.try_into()?,
                &verification_metadata.try_into()?,
            )
            .await
            .map_err(IntoNapiError::into_napi_error)
            .and_then(to_json_object)
    }
}

/// An `OID4VP` response configuration of authorization request object.
#[derive(Clone)]
#[napi(js_name = "AuthResponseOptions", object)]
pub struct JsAuthResponseOptions {
    pub type_: String,
    pub mode: String,
    pub submission_uri: Option<String>,
    pub state: Option<String>,
}

impl TryFrom<JsAuthResponseOptions> for AuthResponseOptions {
    type Error = Error;

    fn try_from(value: JsAuthResponseOptions) -> Result<Self> {
        Ok(Self {
            type_: value.type_.into(),
            mode: value.mode.into(),
            submission_uri: value
                .submission_uri
                .map(|uri| Url::parse(&uri).map_err(|e| Error::from_reason(e.to_string())))
                .transpose()?,
            state: value.state,
        })
    }
}
#[derive(PartialEq)]
#[napi(js_name = "PassAuthRequestObjectType")]
pub enum JsPassAuthRequestObjectType {
    ByValue,
    ByReference,
}

#[derive(Clone)]
#[napi(js_name = "PassAuthRequestObject", object)]
pub struct JsPassAuthRequestObject {
    pub type_: JsPassAuthRequestObjectType,
    pub request_uri: Option<String>,
    pub method: Option<JsHttpMethodForAuth>,
}

impl TryFrom<JsPassAuthRequestObject> for PassAuthRequestObject {
    type Error = Error;
    fn try_from(value: JsPassAuthRequestObject) -> Result<Self> {
        if value.type_ == JsPassAuthRequestObjectType::ByValue {
            Ok(PassAuthRequestObject::ByValue)
        } else {
            let uri = value
                .request_uri
                .ok_or("Request URI missing")
                .map_err(Error::from_reason)?;
            let uri = parse_url_arg(&uri)?;
            let method = value.method.map(|v| v.to_raw());
            Ok(PassAuthRequestObject::ByReference { uri, method })
        }
    }
}

#[derive(Clone)]
#[napi(js_name = "AuthorizationRequestMetadata", object)]
pub struct JsAuthorizationRequestMetadata {
    pub auth_response_options: JsAuthResponseOptions,
    pub pass_auth_request_object: JsPassAuthRequestObject,
    #[napi(ts_type = "Array<TransactionDataItem> | null | undefined")]
    pub transaction_data: Option<Vec<JsonObject>>,
    pub expected_origins: Option<Vec<String>>,
}

impl TryFrom<JsAuthorizationRequestMetadata> for AuthorizationRequestMetadata {
    type Error = Error;
    fn try_from(value: JsAuthorizationRequestMetadata) -> Result<Self> {
        let transaction_data = if let Some(items) = value.transaction_data {
            let mut td = Vec::new();
            for item in items {
                td.push(from_json_object(item)?);
            }
            Some(td)
        } else {
            None
        };

        let expected_origins = if let Some(origins) = value.expected_origins {
            let mut origin_urls = Vec::new();
            for origin in origins {
                origin_urls.push(
                    Url::parse(&origin)
                        .map(|u| u.origin())
                        .map_err(|e| Error::from_reason(e.to_string()))?,
                );
            }
            NonEmptyVec::maybe_new(origin_urls).map(ExpectedOrigins::new)
        } else {
            None
        };

        Ok(Self {
            auth_response_options: value.auth_response_options.try_into()?,
            pass_auth_request_object: value.pass_auth_request_object.try_into()?,
            transaction_data,
            expected_origins,
        })
    }
}

#[derive(Clone)]
#[napi(js_name = "CredentialVerificationMetadata", object)]
pub struct JsCredentialVerificationMetadata {
    #[napi(ts_type = "Array<TransactionDataItem> | null | undefined")]
    pub transaction_data: Option<Vec<JsonObject>>,
}

impl TryFrom<JsCredentialVerificationMetadata> for CredentialVerificationMetadata {
    type Error = Error;
    fn try_from(value: JsCredentialVerificationMetadata) -> Result<Self> {
        let td_items = if let Some(td) = value.transaction_data {
            let mut items = Vec::new();
            for item in td {
                items.push(from_json_object(item)?);
            }
            Some(items)
        } else {
            None
        };
        Ok(Self {
            transaction_data: td_items,
        })
    }
}

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
