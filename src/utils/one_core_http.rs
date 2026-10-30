//! Adapter from the SDK [`HttpClient`] to one-core's HTTP client interface.
//!
//! TODO: find a way to drop this adapter and one-core's `HttpClient` from the SDK.

use crate::http::HttpClient;
use async_trait::async_trait;
use oauth2::http::{Method as OauthHttpMethod, Request as OauthHttpRequest};
use one_core::proto::http_client::HttpClient as OneCoreHttpClient;
use one_core::proto::http_client::{
    Error as OneCoreHttpError, Headers, Method, Request, RequestBuilder, Response, StatusCode,
};
use std::sync::Arc;
use time::Duration;

/// Adapts [`HttpClient`] to the one-core [`OneCoreHttpClient`] interface.
#[derive(Clone)]
pub(crate) struct OneCoreHttpClientAdapter {
    inner: Arc<dyn HttpClient>,
}

impl OneCoreHttpClientAdapter {
    pub(crate) fn new(inner: Arc<dyn HttpClient>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl OneCoreHttpClient for OneCoreHttpClientAdapter {
    fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Get, url)
    }

    fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Post, url)
    }

    fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Put, url)
    }

    fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(Arc::new(self.clone()), Method::Patch, url)
    }

    async fn send(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<Headers>,
        method: Method,
        _timeout: Option<Duration>,
    ) -> Result<Response, OneCoreHttpError> {
        let http_method = match method {
            Method::Get => OauthHttpMethod::GET,
            Method::Post => OauthHttpMethod::POST,
            Method::Put => OauthHttpMethod::PUT,
            Method::Patch => OauthHttpMethod::PATCH,
        };

        let mut builder = OauthHttpRequest::builder().method(http_method).uri(url);

        if let Some(ref headers) = headers {
            for (name, value) in headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
        }

        let request = builder
            .body(body.clone().unwrap_or_default())
            .map_err(|e| OneCoreHttpError::Transport(e.to_string()))?;

        let equs_sdk_response = self
            .inner
            .async_call(request)
            .await
            .map_err(|e| OneCoreHttpError::Transport(e.to_string()))?;

        let resp_headers: Headers = equs_sdk_response
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string())))
            .collect();
        let resp_body = equs_sdk_response.body().to_vec();

        let req = Request {
            body,
            headers: headers.unwrap_or_default(),
            method,
            url: url.to_string(),
            timeout: Some(Duration::minutes(10)),
        };

        Response {
            body: resp_body,
            headers: resp_headers,
            status: StatusCode(equs_sdk_response.status().as_u16()),
            request: req,
        }
        .error_for_status()
    }
}
