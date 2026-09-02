use crate::common::{Error, Result};
use async_trait::async_trait;
use equs_sdk::http::{
    HeaderMap, HeaderName, HeaderValue, HttpClient as EqusSdkHttpClient,
    HttpMethod as EqusSdkHttpMethod, HttpRequest as EqusSdkHttpRequest,
    HttpResponse as EqusSdkHttpResponse, StatusCode, Uri,
};
use equs_sdk::http::{HttpSnafu, Result as EqusSdkResult};
use equs_sdk::reqwest::ReqwestClient;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::OnceLock;

/// Drives reqwest's I/O. `#[uniffi::export(async_runtime = "tokio")]` wraps every
/// exported future in `async_compat::Compat`, which reuses a current tokio handle
/// if one exists and otherwise falls back to a process-wide *single-threaded*
/// runtime. Everything the SDK sends then funnels through that one thread, and on
/// a machine with few cores it is starved by concurrent work until requests stall.
/// Owning a multi-threaded runtime here means `Handle::try_current()` succeeds and
/// the fallback is never used.
static HTTP_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn http_runtime() -> &'static tokio::runtime::Runtime {
    HTTP_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("equs-sdk-http")
            .enable_all()
            .build()
            .expect("failed to build the equs-sdk HTTP runtime")
    })
}

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

impl From<HttpMethod> for EqusSdkHttpMethod {
    fn from(value: HttpMethod) -> Self {
        match value {
            HttpMethod::GET => EqusSdkHttpMethod::GET,
            HttpMethod::POST => EqusSdkHttpMethod::POST,
            HttpMethod::PUT => EqusSdkHttpMethod::PUT,
            HttpMethod::DELETE => EqusSdkHttpMethod::DELETE,
            HttpMethod::HEAD => EqusSdkHttpMethod::HEAD,
            HttpMethod::OPTIONS => EqusSdkHttpMethod::OPTIONS,
            HttpMethod::CONNECT => EqusSdkHttpMethod::CONNECT,
            HttpMethod::PATCH => EqusSdkHttpMethod::PATCH,
            HttpMethod::TRACE => EqusSdkHttpMethod::TRACE,
        }
    }
}
impl TryFrom<EqusSdkHttpMethod> for HttpMethod {
    type Error = Error;

    fn try_from(value: EqusSdkHttpMethod) -> Result<Self> {
        match value {
            EqusSdkHttpMethod::GET => Ok(HttpMethod::GET),
            EqusSdkHttpMethod::POST => Ok(HttpMethod::POST),
            EqusSdkHttpMethod::PUT => Ok(HttpMethod::PUT),
            EqusSdkHttpMethod::DELETE => Ok(HttpMethod::DELETE),
            EqusSdkHttpMethod::HEAD => Ok(HttpMethod::HEAD),
            EqusSdkHttpMethod::OPTIONS => Ok(HttpMethod::OPTIONS),
            EqusSdkHttpMethod::CONNECT => Ok(HttpMethod::CONNECT),
            EqusSdkHttpMethod::PATCH => Ok(HttpMethod::PATCH),
            EqusSdkHttpMethod::TRACE => Ok(HttpMethod::TRACE),
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

impl TryFrom<HttpRequest> for EqusSdkHttpRequest {
    type Error = Error;
    fn try_from(value: HttpRequest) -> Result<Self> {
        let mut req = EqusSdkHttpRequest::new(convert_option_string_to_vec_u8(value.body));

        *req.uri_mut() = value
            .url
            .parse::<Uri>()
            .map_err(|e| Error::HttpRequestParsing(e.to_string()))?;
        *req.method_mut() = value.method.into();
        *req.headers_mut() = parse_json_to_header_map(value.headers)?;

        Ok(req)
    }
}

impl TryFrom<EqusSdkHttpRequest> for HttpRequest {
    type Error = Error;
    fn try_from(value: EqusSdkHttpRequest) -> Result<Self> {
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
impl TryFrom<EqusSdkHttpResponse> for HttpResponse {
    type Error = Error;
    fn try_from(value: EqusSdkHttpResponse) -> Result<Self> {
        Ok(Self {
            status_code: value.status().as_u16(),
            headers: parse_header_map_to_map(value.headers())?,
            body: convert_vec_u8_to_string(value.into_body())?,
        })
    }
}
impl TryFrom<HttpResponse> for EqusSdkHttpResponse {
    type Error = Error;
    fn try_from(value: HttpResponse) -> Result<Self> {
        let headers = parse_json_to_header_map(value.headers)?;
        let mut resp = EqusSdkHttpResponse::new(convert_option_string_to_vec_u8(value.body));
        *resp.headers_mut() = headers;
        *resp.status_mut() = StatusCode::from_u16(value.status_code)
            .map_err(|e| Error::HttpResponseParsing(e.to_string()))?;

        Ok(resp)
    }
}

/// HTTP transport. Must be safe for concurrent use.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait HttpClient: Send + Sync + Debug {
    /// Performs the request and returns the response.
    ///
    /// # Arguments
    /// * `request` - the request to send as given, headers included
    ///
    /// # Returns
    /// The `HttpResponse`.
    ///
    /// # Errors
    /// * `Error.HttpAsyncCall` - no response was obtained, such as a connection or TLS failure
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
impl EqusSdkHttpClient for WrappedHttpClient {
    async fn async_call(&self, request: EqusSdkHttpRequest) -> EqusSdkResult<EqusSdkHttpResponse> {
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
        equs_sdk::reqwest::builder::ReqwestClientBuilder::new()
            .build()
            .map(Self)
            .map_err(|e| Error::Core(e.to_string()))
    }
    #[uniffi::constructor]
    pub fn insecure() -> Result<Self> {
        equs_sdk::reqwest::builder::ReqwestClientBuilder::new()
            .insecure()
            .build()
            .map(Self)
            .map_err(|e| Error::Core(e.to_string()))
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
        let client = self.inner();
        let request: EqusSdkHttpRequest = request.try_into()?;
        http_runtime()
            .spawn(async move { client.async_call(request).await })
            .await
            .map_err(|e| Error::HttpAsyncCall(e.to_string()))?
            .map_err(|e| Error::HttpAsyncCall(e.to_string()))?
            .try_into()
    }
}

#[cfg(debug_assertions)]
#[uniffi::export(async_runtime = "tokio")]
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
