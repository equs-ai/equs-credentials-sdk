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
            url = request.url.as_str(),
            method = request.method.as_str(),
        )
        err(),
    )]
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse> {
        info!("Making HTTP request is started");
        let mut request_builder = self
            .client
            .request(request.method.clone(), request.url.as_str())
            .body(request.body)
            .timeout(Duration::from_secs(30));

        for (name, value) in &request.headers {
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

        Ok(HttpResponse {
            status_code,
            headers,
            body: chunks.to_vec(),
        })
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
    use oauth2::http::{HeaderMap, HeaderValue, Method};
    use oauth2::HttpRequest;
    use reqwest::header::{CONTENT_TYPE, SET_COOKIE};
    use reqwest::StatusCode;
    use rstest::rstest;
    use serde_json::{json, Value};
    use url::Url;

    const MIME_TYPE_TEXT_PLAIN_WITH_CHARSET: &str = "text/plain; charset=utf-8";
    const MIME_TYPE_JSON_WITH_CHARSET: &str = "application/json; charset=utf-8";

    #[tokio::test]
    #[should_panic(expected = "URL scheme is not allowed")]
    async fn reqwest_client_fails_to_send_request_by_http() {
        let client = ReqwestClientBuilder::new().build().unwrap();
        let resp = client
            .async_call(HttpRequest {
                url: Url::parse("http://example.org").unwrap(),
                method: Method::POST,
                headers: HeaderMap::from_iter(vec![(
                    ACCEPT,
                    HeaderValue::from_static(MIME_TYPE_JSON),
                )]),
                body: vec![],
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "index out of bound")]
    async fn reqwest_client_fails_to_send_request_with_crlf_header() {
        let client = ReqwestClientBuilder::new().build().unwrap();
        let resp = client
            .async_call(HttpRequest {
                url: Url::parse("http://example.org").unwrap(),
                method: Method::POST,
                headers: vec![(ACCEPT, HeaderValue::from_static("Bar\r\n"))]
                    .into_iter()
                    .collect(),
                body: vec![],
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "connection closed before message completed")]
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
        let resp = client
            .async_call(HttpRequest {
                url: Url::parse(format!("{url}/test").as_str()).unwrap(),
                method: Method::GET,
                headers: HeaderMap::from_iter(vec![(
                    ACCEPT,
                    HeaderValue::from_static(MIME_TYPE_TEXT_PLAIN),
                )]),
                body: vec![],
            })
            .await
            .unwrap();
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

        let _ = client
            .async_call(HttpRequest {
                url: Url::parse(format!("{}/", server.url()).as_str()).unwrap(),
                method: Method::GET,
                headers: HeaderMap::from_iter(vec![(
                    ACCEPT,
                    HeaderValue::from_static(MIME_TYPE_TEXT_PLAIN),
                )]),
                body: vec![],
            })
            .await
            .unwrap();
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
        let resp = client
            .async_call(HttpRequest {
                url: Url::parse(format!("{}/test", server.url()).as_str()).unwrap(),
                method: Method::GET,
                headers: HeaderMap::from_iter(vec![(
                    ACCEPT,
                    HeaderValue::from_static(MIME_TYPE_TEXT_PLAIN),
                )]),
                body: vec![],
            })
            .await
            .unwrap();
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
        let _ = client
            .async_call(HttpRequest {
                url: Url::parse(format!("{}/", server.url()).as_str()).unwrap(),
                method: Method::GET,
                headers: HeaderMap::from_iter(vec![(
                    ACCEPT,
                    HeaderValue::from_static(MIME_TYPE_TEXT_PLAIN),
                )]),
                body: vec![],
            })
            .await
            .unwrap();
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

        let request = HttpRequest {
            url: Url::parse(&url).unwrap(),
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_str(accept_header).unwrap())]
                .into_iter()
                .collect(),
            body: vec![],
        };

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();

        let resp = client.async_call(request).await.unwrap();
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

        let request = HttpRequest {
            url: Url::parse(&url).unwrap(),
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_str(MIME_TYPE_JSON).unwrap())]
                .into_iter()
                .collect(),
            body: vec![],
        };

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();

        let resp = client.async_call(request).await.unwrap();

        assert!(!resp.headers.contains_key(SET_COOKIE));
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

        let request = HttpRequest {
            url: Url::parse(&url).unwrap(),
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_str(MIME_TYPE_JSON).unwrap())]
                .into_iter()
                .collect(),
            body: vec![],
        };

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();

        client.async_call(request).await.unwrap();
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

        let request = HttpRequest {
            url: Url::parse(&url).unwrap(),
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_static(MIME_TYPE_TEXT_PLAIN))]
                .into_iter()
                .collect(),
            body: vec![],
        };

        let client = ReqwestClientBuilder::new().insecure().build().unwrap();

        let resp = client.async_call(request).await.unwrap();
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

        let mut headers = HeaderMap::new();
        headers.insert("Accept", MIME_TYPE_JSON.parse().unwrap());

        let resp = client
            .async_call(HttpRequest {
                url: Url::parse(format!("{url}/test").as_str()).unwrap(),
                method: Method::GET,
                headers,
                body: vec![],
            })
            .await
            .unwrap();

        let body: Value = serde_json::from_slice(&resp.body).unwrap();

        assert_eq!(resp.status_code, StatusCode::OK);
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

        let resp = client
            .async_call(HttpRequest {
                url: Url::parse(format!("{url}/test").as_str()).unwrap(),
                method: Method::POST,
                headers: HeaderMap::from_iter(vec![(
                    ACCEPT,
                    HeaderValue::from_static(MIME_TYPE_JSON),
                )]),
                body: serde_json::to_vec(&json!({"hello":"world"})).unwrap(),
            })
            .await
            .unwrap();

        let body: Value = serde_json::from_slice(&resp.body).unwrap();

        assert_eq!(resp.status_code, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, json!({"error":"response"}));
    }

    #[tokio::test]
    async fn reqwest_client_fails_on_invalid_url() {
        let client = ReqwestClientBuilder::new().insecure().build().unwrap();

        let res = client
            .async_call(HttpRequest {
                url: Url::parse("http://invalid-url.com").unwrap(),
                method: Method::GET,
                headers: Default::default(),
                body: vec![],
            })
            .await;

        assert!(res.is_err());
    }

    fn resp_data_50kb() -> Vec<u8> {
        vec![0x41; 1024 * 50]
    }
}
