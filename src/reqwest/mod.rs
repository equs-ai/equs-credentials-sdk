use std::time::Duration;

use async_trait::async_trait;
use oauth2::{HttpRequest, HttpResponse};
use reqwest::{Client};
use tracing::{instrument, Level, trace};
use crate::http::{HttpClient, HttpSnafu, Result};

#[derive(Clone)]
pub struct ReqwestClient {
    client: Client,
}

impl ReqwestClient {
    pub fn new(
        https_only: bool,
        invalid_certs: bool,
    ) -> Result<Self> {
        let client = Client::builder()
            .https_only(https_only)
            .danger_accept_invalid_certs(invalid_certs)
            .build()
            .map_err(|err| HttpSnafu { details: err.to_string() }.build())?;

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
        let mut request_builder = self.client
            .request(request.method, request.url.as_str())
            .body(request.body)
            .timeout(Duration::from_secs(5));

        for (name, value) in &request.headers {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }

        let request = request_builder.build()
            .map_err(|err| HttpSnafu { details: err.to_string() }.build())?;

        let response = self.client.execute(request).await
            .map_err(|err| HttpSnafu { details: err.to_string() }.build())?;
        let status_code = response.status();
        let headers = response.headers().to_owned();
        let chunks = response.bytes().await
            .map_err(|err| HttpSnafu { details: err.to_string() }.build())?;

        trace!(response_body = ?{ String::from_utf8(chunks.to_vec()).as_ref() });

        Ok(HttpResponse {
            status_code,
            headers,
            body: chunks.to_vec(),
        })
    }

    async fn static_async(request: HttpRequest) -> Result<HttpResponse> {
        ReqwestClient::new(false, true)?.async_call(request).await
    }
}


