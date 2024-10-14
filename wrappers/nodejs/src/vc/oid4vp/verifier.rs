use crate::utils::{from_json_object, parse_url_arg, to_json_object};
use crate::vc::JsonObject;
use agent_sdk::vc::oid4vp::{
    auth_request_as_url, AuthorizationRequest, AuthorizationResponse, AuthorizationUrlType,
    PresentationSession, Verifier,
};
use napi::{Error, Result};
use napi_derive::napi;

#[napi]
pub struct OID4VPVerifier(Box<dyn Verifier>);

impl OID4VPVerifier {
    pub fn from_verifier<V: Verifier + 'static>(verifier: V) -> OID4VPVerifier {
        OID4VPVerifier(Box::new(verifier))
    }
}

#[napi]
impl OID4VPVerifier {
    #[napi]
    pub async fn create_authorization_request(
        &self,
        presentation_definition: JsonObject,
        response_uri: String,
    ) -> Result<AuthorizationRequestWithSession> {
        let (authorization_request, session) = self
            .0
            .create_authorization_request(
                &from_json_object(presentation_definition)?,
                parse_url_arg(&response_uri)?,
            )
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

        Ok(AuthorizationRequestWithSession {
            authorization_request: authorization_request.into(),
            session: session.try_into()?,
        })
    }

    #[napi]
    pub async fn verify_presentation(
        &self,
        authorization_response: JsAuthorizationResponse,
        session: JsPresentationSession,
    ) -> Result<JsonObject> {
        self.0
            .verify_presentation(&authorization_response.try_into()?, &session.try_into()?)
            .await
            .map_err(|err| Error::from_reason(format!("{:?}", err)))
            .and_then(to_json_object)
    }
}

#[napi(js_name = "AuthorizationRequest", object)]
pub struct JsAuthorizationRequest {
    pub client_id: String,
    pub request_object_jwt: String,
    pub authorization_endpoint: String,
}

#[napi]
pub fn auth_request_as_url_by_reference(
    auth_request: JsAuthorizationRequest,
    request_uri: String,
) -> Result<String> {
    let url = auth_request_as_url(
        &auth_request.try_into()?,
        AuthorizationUrlType::Reference(parse_url_arg(&request_uri)?),
    );

    Ok(url.to_string())
}

#[napi]
pub fn auth_request_as_url_by_value(auth_request: JsAuthorizationRequest) -> Result<String> {
    let url = auth_request_as_url(&auth_request.try_into()?, AuthorizationUrlType::Value);

    Ok(url.to_string())
}

impl From<AuthorizationRequest> for JsAuthorizationRequest {
    fn from(value: AuthorizationRequest) -> Self {
        JsAuthorizationRequest {
            client_id: value.client_id,
            request_object_jwt: value.request_object_jwt,
            authorization_endpoint: value.authorization_endpoint.to_string(),
        }
    }
}

impl TryFrom<JsAuthorizationRequest> for AuthorizationRequest {
    type Error = Error;

    fn try_from(value: JsAuthorizationRequest) -> Result<Self> {
        Ok(AuthorizationRequest {
            client_id: value.client_id,
            request_object_jwt: value.request_object_jwt,
            authorization_endpoint: parse_url_arg(&value.authorization_endpoint)?,
        })
    }
}

#[napi(js_name = "PresentationSession", object)]
pub struct JsPresentationSession {
    pub nonce: String,
    pub presentation_definition: JsonObject,
}

impl TryFrom<PresentationSession> for JsPresentationSession {
    type Error = Error;

    fn try_from(value: PresentationSession) -> Result<Self> {
        Ok(Self {
            nonce: value.nonce.secret().to_string(),
            presentation_definition: to_json_object(value.presentation_definition)?,
        })
    }
}

impl TryFrom<JsPresentationSession> for PresentationSession {
    type Error = Error;

    fn try_from(value: JsPresentationSession) -> Result<Self> {
        Ok(Self {
            nonce: serde_json::from_value(serde_json::Value::String(value.nonce))?,
            presentation_definition: from_json_object(value.presentation_definition)?,
        })
    }
}

#[napi(object)]
pub struct AuthorizationRequestWithSession {
    pub authorization_request: JsAuthorizationRequest,
    pub session: JsPresentationSession,
}

#[napi(js_name = "AuthorizationResponse", object)]
pub struct JsAuthorizationResponse {
    pub vp_token: serde_json::Value,
    pub presentation_submission: JsonObject,
}

impl TryFrom<JsAuthorizationResponse> for AuthorizationResponse {
    type Error = Error;

    fn try_from(value: JsAuthorizationResponse) -> Result<Self> {
        Ok(Self {
            vp_token: value.vp_token,
            presentation_submission: from_json_object(value.presentation_submission)?,
        })
    }
}
