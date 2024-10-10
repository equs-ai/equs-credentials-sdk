use async_trait::async_trait;
use mime::Mime;
use oauth2::http::header::ACCEPT;
use oauth2::http::HeaderValue;
use oauth2::{HttpRequest, HttpResponse};
use reqwest::header::CONTENT_TYPE;
use reqwest::redirect::Policy;
use reqwest::{Client, Response};
use snafu::ensure;
use std::str::{from_utf8, FromStr};
use std::time::Duration;
use tracing::{debug, info, instrument, Level};

use crate::http::{HttpClient, HttpSnafu, Result};

fn req_body_to_string(body: &[u8]) -> &str {
    from_utf8(body).unwrap_or("*** NON-UTF8 characters ***")
}

#[derive(Debug, Clone)]
pub struct ReqwestClient {
    client: Client,
}

impl ReqwestClient {
    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .redirect(Policy::none())
            .build()
            .map_err(|err| {
                HttpSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        Ok(Self { client })
    }
}

impl ReqwestClient {
    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    pub fn unsecure() -> Result<Self> {
        let client = Client::builder()
            .https_only(false)
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|err| {
                HttpSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        Ok(Self { client })
    }

    fn validate_content_type_of_resp(
        content_type_to_accept: &HeaderValue,
        response: &Response,
    ) -> Result<()> {
        let content_type = response.headers().get(CONTENT_TYPE).ok_or_else(|| {
            HttpSnafu {
                details: format!(
                    "Content-type is missed: accepted {:?}, content-type header is missed in response",
                    content_type_to_accept
                ),
            }.build()
        })?;

        let content_type = Self::header_value_to_mime(content_type);
        let content_type_to_accept = Self::header_value_to_mime(content_type_to_accept);

        if let (Some(content_type), Some(content_type_to_accept)) =
            (content_type, content_type_to_accept)
        {
            ensure!(
                content_type_to_accept.essence_str() == content_type.essence_str(),
                HttpSnafu {
                    details: format!(
                        "Content-type is mismatched: accepted {:?} , received {:?}",
                        content_type_to_accept, content_type
                    ),
                }
            );

            for (name, value) in content_type_to_accept.params() {
                let value_to_check = content_type.get_param(name);

                ensure!(
                    value_to_check == Some(value),
                    HttpSnafu {
                        details: format!(
                            "Content-type is mismatched: accepted {:?} , received {:?}",
                            content_type_to_accept, content_type
                        ),
                    }
                );
            }
        }

        Ok(())
    }

    fn header_value_to_mime(header_val: &HeaderValue) -> Option<Mime> {
        header_val
            .to_str()
            .ok()
            .and_then(|c| Mime::from_str(c).ok())
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        fields(
            url = request.url.as_str(),
            method = request.method.as_str(),
            body = ?{ String::from_utf8(request.body.clone()).as_ref() }
        )
        err(),
    )]
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse> {
        info!("Req: {} {}", request.method, request.url);
        debug!("Req body: {}", req_body_to_string(&request.body));
        debug!("Req headers: {:?}", request.headers);

        let content_type_to_accept = request.headers.get(ACCEPT);
        let mut request_builder = self
            .client
            .request(request.method.clone(), request.url.as_str())
            .body(request.body)
            .timeout(Duration::from_secs(5));

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

        if let Some(content_type_to_accept) = content_type_to_accept {
            Self::validate_content_type_of_resp(content_type_to_accept, &response)?;
        }

        let status_code = response.status();
        let headers = response.headers().to_owned();

        let chunks = response.bytes().await.map_err(|err| {
            HttpSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let resp_body = chunks.to_vec();

        info!("Resp: {} {} {}", status_code, request.method, request.url);
        debug!("Resp body: {}", req_body_to_string(&resp_body));
        debug!("Resp headers: {:?}", headers);

        Ok(HttpResponse {
            status_code,
            headers,
            body: resp_body,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::http::HttpClient;
    use crate::reqwest::ReqwestClient;
    use crate::utils::http::MIME_TYPE_JSON;
    use crate::utils::http::MIME_TYPE_TEXT_PLAIN;
    use oauth2::http::header::ACCEPT;
    use oauth2::http::{HeaderMap, HeaderValue, Method};
    use oauth2::HttpRequest;
    use reqwest::header::CONTENT_TYPE;
    use reqwest::StatusCode;
    use rstest::rstest;
    use serde_json::{json, Value};
    use url::Url;

    const MIME_TYPE_TEXT_HTML: &str = "text/html";
    const MIME_TYPE_TEXT_HTML_WITH_CHARSET: &str = "text/html; charset=utf-8";
    const MIME_TYPE_JSON_WITH_CHARSET: &str = "application/json; charset=utf-8";

    #[tokio::test]
    #[should_panic(expected = "URL scheme is not allowed")]
    async fn reqwest_client_fails_to_send_request_by_http() {
        let client = ReqwestClient::new().unwrap();
        let resp = client
            .async_call(HttpRequest {
                url: Url::parse("http://example.org").unwrap(),
                method: Method::POST,
                headers: Default::default(),
                body: vec![],
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "index out of bound")]
    async fn reqwest_client_fails_to_send_request_with_crlf_header() {
        let client = ReqwestClient::new().unwrap();
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
            .with_header(CONTENT_TYPE.as_str(), "text/plain")
            .with_header("content-length", "13")
            .with_body("Hello World!")
            .create();

        let client = ReqwestClient::unsecure().unwrap();
        let resp = client
            .async_call(HttpRequest {
                url: Url::parse(format!("{url}/test").as_str()).unwrap(),
                method: Method::GET,
                headers: Default::default(),
                body: vec![],
            })
            .await
            .unwrap();
    }

    // TODO: Seems mockito adds "text/html" content-type as default, so find a way to respond with empty content-type
    // #[should_panic(expected = "Content-type is missed")] /
    // #[case(("content-length", "12"))]
    #[rstest]
    #[should_panic(expected = "Content-type is mismatched")]
    #[case::different_mimes(MIME_TYPE_TEXT_PLAIN, MIME_TYPE_JSON)]
    #[should_panic(expected = "Content-type is mismatched")]
    #[case::mimes_with_different_params(MIME_TYPE_JSON_WITH_CHARSET, MIME_TYPE_JSON)]
    #[tokio::test]
    async fn handling_response_fails_when_content_type_is_invalid(
        #[case] accept_header: &str,
        #[case] resp_header: &str,
    ) {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), resp_header)
            .with_body("Hello World!")
            .create();

        let request = HttpRequest {
            url: Url::parse("http://example.org").unwrap(),
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_str(accept_header).unwrap())]
                .into_iter()
                .collect(),
            body: vec![],
        };

        let client = ReqwestClient::unsecure().unwrap();

        let resp = client.async_call(request).await.unwrap();
    }

    #[tokio::test]
    async fn handling_response_works_when_essence_of_accepted_header_is_matched() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), MIME_TYPE_TEXT_HTML_WITH_CHARSET)
            .with_body("Hello World!")
            .create();

        let request = HttpRequest {
            url: Url::parse("http://example.org").unwrap(),
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_static(MIME_TYPE_TEXT_HTML))]
                .into_iter()
                .collect(),
            body: vec![],
        };

        let client = ReqwestClient::unsecure().unwrap();

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

        let client = ReqwestClient::unsecure().unwrap();

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

        let client = ReqwestClient::unsecure().unwrap();

        let resp = client
            .async_call(HttpRequest {
                url: Url::parse(format!("{url}/test").as_str()).unwrap(),
                method: Method::POST,
                headers: Default::default(),
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
        let client = ReqwestClient::unsecure().unwrap();

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
}
