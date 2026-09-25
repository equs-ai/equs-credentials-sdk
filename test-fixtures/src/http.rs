//! A URL-keyed [`HttpClient`] stub.
//!
//! Two of the SDK entry points a fixture has to go through take an
//! [`HttpClient`] — the holder service and the status-list lookup. Fixtures make
//! no network calls, so this serves a fixed body per URL and answers `404`
//! everywhere else; an unexpected request therefore fails the test rather than
//! reaching out.

use async_trait::async_trait;
use equs_sdk::http::{HttpClient, HttpRequest, HttpResponse, Result, StatusCode};
use std::collections::HashMap;

/// An [`HttpClient`] that serves a fixed body per URL.
#[derive(Debug, Default, Clone)]
pub struct StaticHttpClient {
    responses: HashMap<String, String>,
}

impl StaticHttpClient {
    /// An empty client: every request answers `404`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serves `body` for `url`.
    #[must_use]
    pub fn with_response(mut self, url: impl Into<String>, body: impl Into<String>) -> Self {
        self.responses.insert(url.into(), body.into());
        self
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl HttpClient for StaticHttpClient {
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse> {
        match self.responses.get(&request.uri().to_string()) {
            Some(body) => Ok(HttpResponse::new(body.clone().into_bytes())),
            None => {
                let mut response = HttpResponse::new(vec![]);
                *response.status_mut() = StatusCode::NOT_FOUND;
                Ok(response)
            }
        }
    }
}
