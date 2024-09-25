use async_trait::async_trait;
use oauth2::{HttpRequest, HttpResponse};
use reqwest::Client;
use std::str::from_utf8;
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
    pub fn new(https_only: bool, invalid_certs: bool) -> Result<Self> {
        let client = Client::builder()
            .https_only(https_only)
            .danger_accept_invalid_certs(invalid_certs)
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
    use oauth2::http::{HeaderMap, Method};
    use oauth2::HttpRequest;
    use reqwest::StatusCode;
    use serde_json::{json, Value};
    use url::Url;

    #[tokio::test]
    async fn reqwest_client_make_successful_call() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/test")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"hello":"world"}).to_string())
            .create();

        let client = ReqwestClient::new(false, true).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/json".parse().unwrap());

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
            .with_header("content-type", "application/json")
            .with_body(json!({"error":"response"}).to_string())
            .create();

        let client = ReqwestClient::new(false, true).unwrap();

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
        let client = ReqwestClient::new(false, true).unwrap();

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
