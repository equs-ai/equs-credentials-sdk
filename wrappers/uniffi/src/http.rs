use crate::common::{Error, Result};
use agent_sdk::http::{
    HeaderMap, HeaderName, HeaderValue, HttpClient as ASDKHttpClient, HttpMethod as ASDKHttpMethod,
    HttpRequest as ASDKHttpRequest, HttpResponse as ASDKHttpResponse, StatusCode, Uri,
};
use agent_sdk::http::{HttpSnafu, Result as ASDKResult};
use agent_sdk::reqwest::ReqwestClient;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(uniffi::Enum)]
pub enum HttpMethod {
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

impl From<HttpMethod> for ASDKHttpMethod {
    fn from(value: HttpMethod) -> Self {
        match value {
            HttpMethod::GET => ASDKHttpMethod::GET,
            HttpMethod::POST => ASDKHttpMethod::POST,
            HttpMethod::PUT => ASDKHttpMethod::PUT,
            HttpMethod::DELETE => ASDKHttpMethod::DELETE,
            HttpMethod::HEAD => ASDKHttpMethod::HEAD,
            HttpMethod::OPTIONS => ASDKHttpMethod::OPTIONS,
            HttpMethod::CONNECT => ASDKHttpMethod::CONNECT,
            HttpMethod::PATCH => ASDKHttpMethod::PATCH,
            HttpMethod::TRACE => ASDKHttpMethod::TRACE,
        }
    }
}
impl TryFrom<ASDKHttpMethod> for HttpMethod {
    type Error = Error;

    fn try_from(value: ASDKHttpMethod) -> Result<Self> {
        match value {
            ASDKHttpMethod::GET => Ok(HttpMethod::GET),
            ASDKHttpMethod::POST => Ok(HttpMethod::POST),
            ASDKHttpMethod::PUT => Ok(HttpMethod::PUT),
            ASDKHttpMethod::DELETE => Ok(HttpMethod::DELETE),
            ASDKHttpMethod::HEAD => Ok(HttpMethod::HEAD),
            ASDKHttpMethod::OPTIONS => Ok(HttpMethod::OPTIONS),
            ASDKHttpMethod::CONNECT => Ok(HttpMethod::CONNECT),
            ASDKHttpMethod::PATCH => Ok(HttpMethod::PATCH),
            ASDKHttpMethod::TRACE => Ok(HttpMethod::TRACE),
            _ => Err(Error::HttpMethodParsing("Invalid HTTP Method".to_string())),
        }
    }
}

#[derive(uniffi::Record)]
pub struct HttpRequest {
    pub url: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

impl TryFrom<HttpRequest> for ASDKHttpRequest {
    type Error = Error;
    fn try_from(value: HttpRequest) -> Result<Self> {
        let mut req = ASDKHttpRequest::new(convert_option_string_to_vec_u8(value.body));

        *req.uri_mut() = value
            .url
            .parse::<Uri>()
            .map_err(|e| Error::HttpRequestParsing(e.to_string()))?;
        *req.method_mut() = value.method.into();
        *req.headers_mut() = parse_json_to_header_map(value.headers)?;

        Ok(req)
    }
}

impl TryFrom<ASDKHttpRequest> for HttpRequest {
    type Error = Error;
    fn try_from(value: ASDKHttpRequest) -> Result<Self> {
        let method = value.method().to_owned().try_into()?;
        Ok(Self {
            url: value.uri().to_string(),
            method,
            headers: parse_header_map_to_map(value.headers())?,
            body: convert_vec_u8_to_string(value.into_body())?,
        })
    }
}

#[derive(uniffi::Record)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}
impl TryFrom<ASDKHttpResponse> for HttpResponse {
    type Error = Error;
    fn try_from(value: ASDKHttpResponse) -> Result<Self> {
        Ok(Self {
            status_code: value.status().as_u16(),
            headers: parse_header_map_to_map(value.headers())?,
            body: convert_vec_u8_to_string(value.into_body())?,
        })
    }
}
impl TryFrom<HttpResponse> for ASDKHttpResponse {
    type Error = Error;
    fn try_from(value: HttpResponse) -> Result<Self> {
        let headers = parse_json_to_header_map(value.headers)?;
        let mut resp = ASDKHttpResponse::new(convert_option_string_to_vec_u8(value.body));
        *resp.headers_mut() = headers;
        *resp.status_mut() = StatusCode::from_u16(value.status_code)
            .map_err(|e| Error::HttpResponseParsing(e.to_string()))?;

        Ok(resp)
    }
}

#[uniffi::export(with_foreign)]
#[async_trait]
pub trait HttpClient: Send + Sync + Debug {
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse>;
}

#[derive(Debug, Clone)]
pub struct WrappedHttpClient(Arc<dyn HttpClient>);

impl WrappedHttpClient {
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        WrappedHttpClient(http_client)
    }
    pub fn inner(&self) -> Arc<dyn HttpClient> {
        self.0.to_owned()
    }
}

#[async_trait]
impl ASDKHttpClient for WrappedHttpClient {
    async fn async_call(&self, request: ASDKHttpRequest) -> ASDKResult<ASDKHttpResponse> {
        let request = request.try_into().map_err(|e: Error| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        })?;
        let result = self.inner().async_call(request).await.map_err(|e| {
            HttpSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        Ok(result.try_into().map_err(|_| {
            HttpSnafu {
                details: "failed to convert response".to_string(),
            }
            .build()
        })?)
    }
}

#[derive(uniffi::Object, Debug)]
pub struct ReqwestHttpClient(ReqwestClient);

#[uniffi::export()]
impl ReqwestHttpClient {
    #[uniffi::constructor]
    pub fn new() -> Result<Self> {
        agent_sdk::reqwest::builder::ReqwestClientBuilder::new()
            .build()
            .map(Self)
            .map_err(|e| Error::Kms(e.to_string()))
    }
    #[uniffi::constructor]
    pub fn insecure() -> Result<Self> {
        agent_sdk::reqwest::builder::ReqwestClientBuilder::new()
            .insecure()
            .build()
            .map(Self)
            .map_err(|e| Error::Kms(e.to_string()))
    }
}

impl ReqwestHttpClient {
    pub fn inner(&self) -> ReqwestClient {
        self.0.to_owned()
    }
}

#[uniffi::export(async_runtime = "tokio")]
#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse> {
        self.inner()
            .async_call(request.try_into()?)
            .await
            .map_err(|e| Error::HttpAsyncCall(e.to_string()))?
            .try_into()
    }
}

#[uniffi::export()]
async fn for_http_request_test(
    client: Arc<dyn HttpClient>,
    request: HttpRequest,
) -> Result<HttpResponse> {
    client.async_call(request).await
}

fn parse_json_to_header_map(value: HashMap<String, String>) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();

    for (key, value) in value {
        let header_name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|e| Error::HttpRequestParsing(e.to_string()))?;

        let header_value =
            HeaderValue::from_str(&value).map_err(|e| Error::HttpRequestParsing(e.to_string()))?;

        headers.insert(header_name, header_value);
    }
    Ok(headers)
}
fn parse_header_map_to_map(value: &HeaderMap) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
    for (key, value) in value.iter() {
        let value_str = value
            .to_str()
            .map_err(|e| Error::HttpResponseParsing(e.to_string()))?;

        headers.insert(key.to_string(), value_str.to_owned());
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
    let result = String::from_utf8(value).map_err(|e| Error::HttpResponseParsing(e.to_string()))?;
    Ok(Some(result))
}
