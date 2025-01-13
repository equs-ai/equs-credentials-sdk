pub mod builder;
pub(super) mod middleware;
pub mod validators;

use async_trait::async_trait;
use oauth2::{HttpRequest, HttpResponse};
use reqwest_middleware::ClientWithMiddleware;
use std::time::Duration;
use tracing::{info, instrument};

use crate::http::{HttpClient, HttpError, HttpSnafu, Result};

#[derive(Debug, Clone)]
pub struct ReqwestClient {
    client: ClientWithMiddleware,
}

#[async_trait]
impl HttpClient for ReqwestClient {
    #[instrument(
        skip_all,
        name = "HTTP async call"
        fields(
            url = request.uri().to_string(),
            method = request.method().as_str(),
        )
        err(),
    )]
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse> {
        let (parts, body) = request.into_parts();
        info!("Making HTTP request is started");
        let mut request_builder = self
            .client
            .request(parts.method, parts.uri.to_string())
            .body(body)
            .timeout(Duration::from_secs(30));

        for (name, value) in parts.headers.iter() {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }

        let req = request_builder.build().map_err(|err| {
            HttpSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let response = self.client.execute(req).await.map_err(|err| {
            HttpSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let status_code = response.status();
        let headers = response.headers().to_owned();

        let chunks = response.bytes().await.map_err(|err| {
            HttpSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        info!("HTTP response is successfully handled: status code = {status_code}");

        let resp_body = chunks.to_vec();
        let mut response = HttpResponse::new(resp_body);
        *response.status_mut() = status_code;
        *response.headers_mut() = headers;

        Ok(response)
    }
}

impl From<reqwest::Error> for HttpError {
    fn from(value: reqwest::Error) -> Self {
        HttpSnafu {
            details: value.to_string(),
        }
        .build()
    }
}

#[cfg(test)]
mod tests {
    use crate::http::HttpClient;
    use crate::reqwest::builder::ReqwestClientBuilder;
    use crate::utils::data_size::DataSize;
    use crate::utils::http::MIME_TYPE_JSON;
    use crate::utils::http::MIME_TYPE_TEXT_PLAIN;
    use oauth2::http::header::ACCEPT;
    use oauth2::http::{HeaderName, HeaderValue, Method, Uri};
    use oauth2::{http, HttpRequest};
    use reqwest::header::{CONTENT_TYPE, SET_COOKIE};
    use reqwest::StatusCode;
    use rstest::rstest;
    use serde_json::{json, Value};
    use std::str::FromStr;

    const MIME_TYPE_TEXT_PLAIN_WITH_CHARSET: &str = "text/plain; charset=utf-8";
    const MIME_TYPE_JSON_WITH_CHARSET: &str = "application/json; charset=utf-8";

    fn sample_request(
        uri: &str,
        method: Method,
        header: (HeaderName, &str),
        body: Vec<u8>,
    ) -> HttpRequest {
        http::request::Builder::new()
            .uri(uri)
            .method(method)
            .header(header.0, header.1)
            .body(vec![])
            .unwrap()
    }

    #[tokio::test]
    #[should_panic(expected = "builder error for url (http://example.org/)")]
    async fn reqwest_client_fails_to_send_request_by_http() {
        let client = ReqwestClientBuilder::new().build().unwrap();
        let req = sample_request(
            "http://example.org",
            Method::POST,
            (ACCEPT, MIME_TYPE_JSON),
            vec![],
        );

        let resp = client.async_call(req).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "index out of bound")]
    async fn reqwest_client_fails_to_send_request_with_crlf_header() {
        let client = ReqwestClientBuilder::new().build().unwrap();

        let mut request = HttpRequest::new(vec![]);
        *request.method_mut() = Method::POST;
        *request.headers_mut() = vec![(ACCEPT, HeaderValue::from_static("Bar\r\n"))]
            .into_iter()
            .collect();
        *request.uri_mut() = Uri::from_str("http://example.org").unwrap();

        let resp = client.async_call(request).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "error sending request")]
    async fn handling_response_fails_when_content_length_is_mismatched() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_TEXT_PLAIN)
            .with_header("content-length", "13")
            .with_body("Hello World!")
            .create();

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();
        let req = sample_request(
            format!("{url}/test").as_str(),
            Method::GET,
            (ACCEPT, MIME_TYPE_TEXT_PLAIN),
            vec![],
        );
        let resp = client.async_call(req).await.unwrap();
    }

    #[rstest]
    #[case::unlimited(None)]
    #[case::limited_1mb(Some(DataSize::MBytes(1).into()))]
    #[case::limited_50kb(Some(DataSize::KBytes(50).into()))]
    #[tokio::test]
    async fn reqwest_client_succeeds_when_response_size_does_not_exceed_the_limit(
        #[case] limits: Option<usize>,
    ) {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_TEXT_PLAIN)
            .with_body(resp_data_50kb())
            .create();

        let mut client_builder = ReqwestClientBuilder::new().insecure();

        if let Some(response_limits) = limits {
            client_builder = client_builder.with_response_content_size_limit(response_limits)
        }
        let client = client_builder.build().unwrap();
        let req = sample_request(
            format!("{}/", server.url()).as_str(),
            Method::GET,
            (ACCEPT, MIME_TYPE_TEXT_PLAIN),
            vec![],
        );
        let _ = client.async_call(req).await.unwrap();
    }

    #[rstest]
    #[should_panic(expected = "content length value 51200 exceeds limit")]
    #[case::limited_10kb(DataSize::KBytes(10).into())]
    #[tokio::test]
    async fn reqwest_client_fails_when_content_length_is_bigger_than_the_limit(
        #[case] response_limit: usize,
    ) {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_TEXT_PLAIN)
            .with_body(resp_data_50kb())
            .create();

        let client = ReqwestClientBuilder::new()
            .insecure()
            .with_response_content_size_limit(response_limit)
            .build()
            .unwrap();
        let req = sample_request(
            format!("{}/test", server.url()).as_str(),
            Method::GET,
            (ACCEPT, MIME_TYPE_TEXT_PLAIN),
            vec![],
        );
        let resp = client.async_call(req).await.unwrap();
    }

    #[rstest]
    #[should_panic(expected = "response body size exceeds the limit")]
    #[case::limited_10kb(DataSize::KBytes(10).into())]
    #[tokio::test]
    async fn reqwest_client_fails_when_response_body_size_exceeds_the_limit(
        #[case] response_limit: usize,
    ) {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_TEXT_PLAIN)
            .with_chunked_body(|w| w.write_all(&resp_data_50kb()))
            .create();

        let client = ReqwestClientBuilder::new()
            .insecure()
            .with_response_content_size_limit(response_limit)
            .build()
            .unwrap();
        let req = sample_request(
            format!("{}/", server.url()).as_str(),
            Method::GET,
            (ACCEPT, MIME_TYPE_TEXT_PLAIN),
            vec![],
        );

        let _ = client.async_call(req).await.unwrap();
    }

    #[rstest]
    #[should_panic(expected = "Content-type is mismatched")]
    #[case::unaccepted_content_response_type(
        MIME_TYPE_TEXT_PLAIN,
        MIME_TYPE_JSON,
        "{\"hello\":\"world\"}"
    )]
    #[should_panic(expected = "Response body is not a json")]
    #[case::unaccepted_response_with_html_body(
        MIME_TYPE_JSON,
        MIME_TYPE_JSON,
        "<html><body>Hello World!</body></html>"
    )]
    #[should_panic(expected = "Response body is not a json")]
    #[case::unaccepted_response_with_xml_body(
        MIME_TYPE_JSON,
        MIME_TYPE_JSON,
        "<note><body>XML Content</body></note>"
    )]
    #[should_panic(expected = "Response body is not a json")]
    #[case::unaccepted_response_with_js_body(
        MIME_TYPE_JSON,
        MIME_TYPE_JSON,
        "console.log('Hello World!');"
    )]
    #[should_panic(expected = "Response body is not a json")]
    #[case::unaccepted_response_with_css_body(
        MIME_TYPE_JSON,
        MIME_TYPE_JSON,
        "body { background-color: red; }"
    )]
    #[should_panic(expected = "Content-type is mismatched")]
    #[case::different_mimes(MIME_TYPE_TEXT_PLAIN, MIME_TYPE_JSON, "Hello World!")]
    #[should_panic(expected = "Content-type is mismatched")]
    #[case::mimes_with_different_params(
        MIME_TYPE_JSON_WITH_CHARSET,
        MIME_TYPE_JSON,
        "{\"hello\":\"world\"}"
    )]
    #[tokio::test]
    async fn handling_response_fails_when_content_type_is_invalid(
        #[case] accept_header: &str,
        #[case] resp_header: &str,
        #[case] resp_body: &str,
    ) {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), resp_header)
            .with_body(resp_body)
            .create();
        let req = sample_request(&url, Method::GET, (ACCEPT, accept_header), vec![]);

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();
        let resp = client.async_call(req).await.unwrap();
    }

    #[tokio::test]
    async fn set_cookie_header_should_be_removed_after_handling_response() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_JSON)
            .with_header(SET_COOKIE.as_str(), "username=john_doe; Path=/; HttpOnly")
            .with_body("{\"hello\":\"world\"}")
            .create();
        let req = sample_request(&url, Method::GET, (ACCEPT, MIME_TYPE_JSON), vec![]);
        let client = ReqwestClientBuilder::new().insecure().build().unwrap();
        let resp = client.async_call(req).await.unwrap();

        assert!(!resp.headers().contains_key(SET_COOKIE));
    }

    #[tokio::test]
    #[should_panic(expected = "Content-type is mismatched")]
    async fn duplicated_header_should_fail_after_handling_response() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_TEXT_PLAIN)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_JSON)
            .with_body("{\"hello\":\"world\"}")
            .create();
        let req = sample_request(&url, Method::GET, (ACCEPT, MIME_TYPE_JSON), vec![]);

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();
        client.async_call(req).await.unwrap();
    }

    #[tokio::test]
    async fn handling_response_works_when_essence_of_accepted_header_is_matched() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_TEXT_PLAIN_WITH_CHARSET)
            .with_body("Hello World!")
            .create();

        let req = sample_request(&url, Method::GET, (ACCEPT, MIME_TYPE_TEXT_PLAIN), vec![]);
        let client = ReqwestClientBuilder::new().insecure().build().unwrap();

        let resp = client.async_call(req).await.unwrap();
    }

    #[tokio::test]
    async fn reqwest_client_make_successful_call() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_JSON)
            .with_body(json!({"hello":"world"}).to_string())
            .create();

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();
        let req = sample_request(
            format!("{url}/test").as_str(),
            Method::GET,
            (ACCEPT, MIME_TYPE_JSON),
            vec![],
        );
        let resp = client.async_call(req).await.unwrap();

        let body: Value = serde_json::from_slice(resp.body()).unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body, json!({"hello":"world"}));
    }

    #[tokio::test]
    async fn reqwest_client_handles_5xx_error() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("POST", "/test")
            .with_status(500)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_JSON)
            .with_body(json!({"error":"response"}).to_string())
            .create();

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();

        let req = sample_request(
            format!("{url}/test").as_str(),
            Method::POST,
            (ACCEPT, MIME_TYPE_JSON),
            serde_json::to_vec(&json!({"hello":"world"})).unwrap(),
        );
        let resp = client.async_call(req).await.unwrap();

        let body: Value = serde_json::from_slice(resp.body()).unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, json!({"error":"response"}));
    }

    #[tokio::test]
    async fn reqwest_client_fails_on_invalid_url() {
        let client = ReqwestClientBuilder::new().insecure().build().unwrap();
        let req = sample_request(
            "http://invalid-url.com",
            Method::GET,
            (ACCEPT, MIME_TYPE_TEXT_PLAIN),
            vec![],
        );
        let res = client.async_call(req).await;

        assert!(res.is_err());
    }

    fn resp_data_50kb() -> Vec<u8> {
        vec![0x41; 1024 * 50]
    }
}
