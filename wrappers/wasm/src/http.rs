use agent_sdk::http::HttpClient as ASDKHttpClient;
use agent_sdk::reqwest::ReqwestClient;
use js_sys::{Object, Promise, Reflect};
use oauth2::http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "HttpRequest")]
    pub type JsHttpRequest;

    #[wasm_bindgen(method, getter)]
    pub fn url(this: &JsHttpRequest) -> String;

    #[wasm_bindgen(method, getter)]
    pub fn method(this: &JsHttpRequest) -> String;

    #[wasm_bindgen(method, getter)]
    pub fn headers(this: &JsHttpRequest) -> JsValue;

    #[wasm_bindgen(method, getter)]
    pub fn body(this: &JsHttpRequest) -> Option<String>;
}

/// An enum of HTTP methods available for making requests.
///
/// This enum includes commonly used HTTP methods
#[derive(Clone, Copy, Debug)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Connect,
    Patch,
    Trace,
}

pub struct HttpRequest {
    url: String,
    method: HttpMethod,
    headers: JsValue,
    body: Option<String>,
}

impl TryFrom<JsHttpRequest> for HttpRequest {
    type Error = JsError;
    fn try_from(value: JsHttpRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            url: value.url(),
            method: value.method().try_into()?,
            headers: value.headers(),
            body: value.body(),
        })
    }
}

impl TryFrom<String> for HttpMethod {
    type Error = JsError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(match value.as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            "CONNECT" => HttpMethod::Connect,
            "PATCH" => HttpMethod::Patch,
            "TRACE" => HttpMethod::Trace,
            _ => Err(JsError::new(
                format!("Invalid HTTP Method value: {}", value).as_str(),
            ))?,
        })
    }
}

impl From<HttpMethod> for Method {
    fn from(value: HttpMethod) -> Self {
        match value {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Options => Method::OPTIONS,
            HttpMethod::Connect => Method::CONNECT,
            HttpMethod::Patch => Method::PATCH,
            HttpMethod::Trace => Method::TRACE,
        }
    }
}

impl TryFrom<HttpRequest> for oauth2::http::Request<Vec<u8>> {
    type Error = JsError;

    fn try_from(value: HttpRequest) -> Result<Self, Self::Error> {
        let uri = value.url.parse::<Uri>().map_err(JsError::from)?;

        let headers = parse_js_headers(&value.headers)?;

        let body = convert_option_string_to_vec_u8(value.body);

        let mut req = oauth2::http::Request::builder()
            .method::<HttpMethod>(value.method)
            .uri(uri)
            .body(body)
            .map_err(JsError::from)?;

        *req.headers_mut() = headers;

        Ok(req)
    }
}

#[wasm_bindgen]
pub struct HttpResponse {
    status_code: u16,
    headers: JsValue,
    body: Option<String>,
}

#[wasm_bindgen]
impl HttpResponse {
    /// The HTTP status code of the response.
    #[wasm_bindgen(getter, js_name = statusCode)]
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    /// The HTTP headers of the response.
    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> JsValue {
        self.headers.clone()
    }

    /// The body of the response.
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Option<String> {
        self.body.clone()
    }
}

fn parse_js_headers(js_headers: &JsValue) -> Result<HeaderMap, JsError> {
    if js_headers.is_null() || js_headers.is_undefined() {
        return Ok(HeaderMap::default());
    }

    if !js_headers.is_object() {
        return Err(JsError::new("Headers is not an object"));
    }

    Ok(process_headers(js_headers))
}

fn process_headers(js_headers: &JsValue) -> HeaderMap {
    let mut headers = HeaderMap::new();

    let js_obj = Object::from(js_headers.to_owned());
    let keys = js_sys::Object::keys(&js_obj);
    let keys_len = keys.length();

    for i in 0..keys_len {
        let key = keys.get(i);
        let key_str = match key.as_string() {
            Some(s) => s,
            None => {
                web_sys::console::warn_1(&JsValue::from_str("Skipping non-string header key"));
                continue;
            }
        };

        let value = match Reflect::get(&js_obj, &key) {
            Ok(v) => v,
            Err(e) => {
                web_sys::console::warn_2(
                    &JsValue::from_str(&format!("Failed to get header value for key {}", key_str)),
                    &e,
                );
                continue;
            }
        };

        let value_str = match value.as_string() {
            Some(s) => s,
            None => {
                web_sys::console::warn_1(&JsValue::from_str(&format!(
                    "Header value for '{}' is not a string",
                    key_str
                )));
                continue;
            }
        };

        let header_name = match HeaderName::from_bytes(key_str.as_bytes()) {
            Ok(name) => name,
            Err(e) => {
                web_sys::console::warn_1(&JsValue::from_str(&format!(
                    "Invalid header name '{}': {}",
                    key_str, e
                )));
                continue;
            }
        };

        let header_value = match HeaderValue::from_str(&value_str) {
            Ok(val) => val,
            Err(e) => {
                web_sys::console::warn_1(&JsValue::from_str(&format!(
                    "Invalid header value for '{}': {}",
                    key_str, e
                )));
                continue;
            }
        };

        headers.insert(header_name, header_value);
    }

    headers
}

fn convert_option_string_to_vec_u8(value: Option<String>) -> Vec<u8> {
    value.map(|v| v.into_bytes()).unwrap_or_default()
}

#[wasm_bindgen]
pub struct ReqwestHttpClient(ReqwestClient);

#[wasm_bindgen]
impl ReqwestHttpClient {
    /// Creates a new `HttpClient` instance using the default, secure configuration.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<ReqwestHttpClient, JsError> {
        agent_sdk::reqwest::builder::ReqwestClientBuilder::new()
            .build()
            .map(|client| ReqwestHttpClient(client))
            .map_err(JsError::from)
    }

    /// Creates a new `HttpClient` instance with an insecure configuration.
    #[wasm_bindgen]
    pub fn insecure() -> Result<ReqwestHttpClient, JsError> {
        agent_sdk::reqwest::builder::ReqwestClientBuilder::new()
            .insecure()
            .build()
            .map(|client| ReqwestHttpClient(client))
            .map_err(JsError::from)
    }

    /// Asynchronously sends an HTTP request and returns an `HttpResponse`.
    ///
    /// # Arguments
    ///
    /// * `request` - An `HttpRequest` instance.
    ///
    /// # Returns
    ///
    /// An `HttpResponse` object.
    ///
    /// # Errors
    ///
    /// Errors may occur if:
    /// - The asynchronous HTTP call fails (e.g., network issues, server errors).
    /// - The response headers or body cannot be processed correctly.
    #[wasm_bindgen(js_name = asyncCall, unchecked_return_type = "Promise<HttpResponse>")]
    pub fn async_call(&self, request: JsHttpRequest) -> Promise {
        let client = self.0.clone();

        let request: HttpRequest = request.try_into().unwrap();

        web_sys::console::info_1(&JsValue::from(format!(
            "Making HTTP request is started: method - {:?}, url - {}",
            request.method, request.url,
        )));

        log_body(request.body.clone(), "Request");

        future_to_promise(async move {
            let request =
                oauth2::http::Request::<Vec<u8>>::try_from(request).map_err(JsError::from)?;

            let response = client.async_call(request).await.map_err(JsError::from)?;

            let status = response.status().as_u16();

            let js_headers = Object::new();
            for (name, value) in response.headers().iter() {
                let header_name = name.as_str();
                let header_value = match value.to_str() {
                    Ok(v) => v,
                    Err(e) => {
                        web_sys::console::warn_1(&JsValue::from_str(&format!(
                            "Skipping non-UTF8 header '{}': {}",
                            header_name, e
                        )));
                        continue;
                    }
                };

                if let Err(e) = Reflect::set(
                    &js_headers,
                    &JsValue::from_str(header_name),
                    &JsValue::from_str(header_value),
                ) {
                    web_sys::console::warn_2(
                        &JsValue::from_str(&format!("Failed to set header '{}'", header_name)),
                        &e,
                    );
                }
            }

            let body = String::from_utf8_lossy(response.body()).into_owned();

            let response = HttpResponse {
                status_code: status,
                headers: js_headers.into(),
                body: if body.is_empty() { None } else { Some(body) },
            };

            web_sys::console::info_1(&JsValue::from(format!(
                "HTTP response is successfully handled: status code = {:?}",
                response.status_code
            )));
            log_body(response.body.clone(), "Response");

            Ok(JsValue::from(response))
        })
    }
}

impl ReqwestHttpClient {
    pub fn inner(&self) -> ReqwestClient {
        self.0.clone()
    }
}

fn log_body(optional_body: Option<String>, prefix: &str) {
    optional_body
        .map(|b| {
            let parsed_body = serde_json::to_string(&b).unwrap_or_else(|_| b.to_owned());
            web_sys::console::debug_1(&JsValue::from(format!("{} body:\n{}", prefix, parsed_body)));
        })
        .unwrap_or(web_sys::console::debug_1(&JsValue::from(format!(
            "{} body is empty",
            prefix
        ))));
}
