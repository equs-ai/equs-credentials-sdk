use crate::vc::JsonObject;
use agent_sdk::http;
use agent_sdk::http::{HttpClient, HttpSnafu};
use agent_sdk::reqwest::ReqwestClient;
use async_trait::async_trait;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi::{Error, Result};
use napi_derive::napi;
use oauth2::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use oauth2::{HttpRequest, HttpResponse};
use serde_json::{Map, Value};

#[napi(js_name = "HttpMethod")]
pub enum JsHttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    CONNECT,
    PATCH,
    TRACE,
}

impl From<JsHttpMethod> for Method {
    fn from(value: JsHttpMethod) -> Self {
        match value {
            JsHttpMethod::GET => Method::GET,
            JsHttpMethod::POST => Method::POST,
            JsHttpMethod::PUT => Method::PUT,
            JsHttpMethod::DELETE => Method::DELETE,
            JsHttpMethod::HEAD => Method::HEAD,
            JsHttpMethod::OPTIONS => Method::OPTIONS,
            JsHttpMethod::CONNECT => Method::CONNECT,
            JsHttpMethod::PATCH => Method::PATCH,
            JsHttpMethod::TRACE => Method::TRACE,
        }
    }
}

impl TryFrom<&Method> for JsHttpMethod {
    type Error = Error;
    fn try_from(value: &Method) -> Result<Self> {
        match *value {
            Method::GET => Ok(JsHttpMethod::GET),
            Method::POST => Ok(JsHttpMethod::POST),
            Method::PUT => Ok(JsHttpMethod::PUT),
            Method::DELETE => Ok(JsHttpMethod::DELETE),
            Method::HEAD => Ok(JsHttpMethod::HEAD),
            Method::OPTIONS => Ok(JsHttpMethod::OPTIONS),
            Method::CONNECT => Ok(JsHttpMethod::CONNECT),
            Method::PATCH => Ok(JsHttpMethod::PATCH),
            Method::TRACE => Ok(JsHttpMethod::TRACE),
            _ => Err(Error::from_reason("Invalid HTTP method")),
        }
    }
}

#[napi(object, js_name = "HttpRequest")]
pub struct JsHttpRequest {
    pub url: String,
    pub method: JsHttpMethod,
    pub headers: JsonObject,
    pub body: Option<String>,
}

impl TryFrom<JsHttpRequest> for HttpRequest {
    type Error = Error;
    fn try_from(value: JsHttpRequest) -> Result<Self> {
        let mut req = HttpRequest::new(convert_option_string_to_vec_u8(value.body));

        *req.uri_mut() = value
            .url
            .parse::<Uri>()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        *req.method_mut() = value.method.into();
        *req.headers_mut() = parse_json_to_header_map(value.headers)?;

        Ok(req)
    }
}

impl TryFrom<HttpRequest> for JsHttpRequest {
    type Error = Error;
    fn try_from(value: HttpRequest) -> Result<Self> {
        Ok(Self {
            url: value.uri().to_string(),
            method: value.method().try_into()?,
            headers: parse_header_map_to_map(value.headers())?,
            body: convert_vec_u8_to_string(value.into_body())?,
        })
    }
}

#[napi(object, js_name = "HttpResponse")]
pub struct JsHttpResponse {
    pub status_code: u16,
    pub headers: JsonObject,
    pub body: Option<String>,
}

impl TryFrom<HttpResponse> for JsHttpResponse {
    type Error = Error;
    fn try_from(value: HttpResponse) -> Result<Self> {
        Ok(Self {
            status_code: value.status().as_u16(),
            headers: parse_header_map_to_map(value.headers())?,
            body: convert_vec_u8_to_string(value.into_body())?,
        })
    }
}

impl TryFrom<JsHttpResponse> for HttpResponse {
    type Error = Error;
    fn try_from(value: JsHttpResponse) -> Result<Self> {
        let headers = parse_json_to_header_map(value.headers)?;
        let mut resp = HttpResponse::new(convert_option_string_to_vec_u8(value.body));
        *resp.headers_mut() = headers;
        *resp.status_mut() = StatusCode::from_u16(value.status_code)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(resp)
    }
}

#[napi(js_name = "HttpClient", object, object_to_js = false)]
pub struct JsHttpClient {
    #[napi(ts_type = "(request: HttpRequest) => Promise<HttpResponse>")]
    pub async_call: ThreadsafeFunction<JsHttpRequest, ErrorStrategy::Fatal>,
}

#[async_trait]
impl HttpClient for JsHttpClient {
    async fn async_call(&self, request: HttpRequest) -> http::Result<HttpResponse> {
        let js_http_request = request.try_into().map_err(|e: Error| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        let promise_js_http_response = self
            .async_call
            .call_async::<Promise<JsHttpResponse>>(js_http_request)
            .await
            .map_err(|e| {
                HttpSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        let js_http_response = promise_js_http_response.await.map_err(|e| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        let http_response = js_http_response.try_into().map_err(|e: Error| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        Ok(http_response)
    }
}

#[napi]
pub struct ReqwestHttpClient(ReqwestClient);

#[napi]
impl ReqwestHttpClient {
    #[napi(constructor)]
    pub fn new() -> Result<Self> {
        agent_sdk::reqwest::builder::ReqwestClientBuilder::new()
            .build()
            .map(ReqwestHttpClient)
            .map_err(|e| Error::from_reason(e.to_string()))
    }
    #[napi]
    pub async fn async_call(&self, request: JsHttpRequest) -> Result<JsHttpResponse> {
        self.0
            .async_call(request.try_into()?)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?
            .try_into()
    }
    pub fn inner(&self) -> ReqwestClient {
        self.0.clone()
    }
}
#[cfg(debug_assertions)]
#[napi]
impl ReqwestHttpClient {
    #[cfg(debug_assertions)]
    #[napi(factory)]
    pub fn insecure() -> Result<ReqwestHttpClient> {
        agent_sdk::reqwest::builder::ReqwestClientBuilder::new()
            .insecure()
            .build()
            .map(ReqwestHttpClient)
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

fn parse_json_to_header_map(value: JsonObject) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();

    for (key, value) in value {
        let header_name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let header_value_str = value.as_str().ok_or_else(|| {
            napi::Error::from_reason(format!(
                "value of the header '{header_name}' is not a string"
            ))
        })?;

        let header_value = HeaderValue::from_str(header_value_str)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        headers.insert(header_name, header_value);
    }
    Ok(headers)
}
fn parse_header_map_to_map(value: &HeaderMap) -> Result<JsonObject> {
    let mut headers = Map::new();
    for (key, value) in value.iter() {
        let value_str = value
            .to_str()
            .map_err(|e| Error::from_reason(e.to_string()))?;

        headers.insert(key.to_string(), Value::String(value_str.to_owned()));
    }
    Ok(headers)
}

fn convert_option_string_to_vec_u8(value: Option<String>) -> Vec<u8> {
    if let Some(value) = value {
        value.as_bytes().to_vec()
    } else {
        Vec::new()
    }
}
fn convert_vec_u8_to_string(value: Vec<u8>) -> Result<Option<String>> {
    if value.is_empty() {
        return Ok(None);
    }
    let result = String::from_utf8(value).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(Some(result))
}

#[napi]
pub async fn for_http_request_test(
    client: JsHttpClient,
    req: JsHttpRequest,
) -> Result<JsHttpResponse> {
    client
        .async_call(req.try_into()?)
        .await
        .map_err(|e| Error::from_reason(e.to_string()))
        .and_then(|v| v.try_into())
}
