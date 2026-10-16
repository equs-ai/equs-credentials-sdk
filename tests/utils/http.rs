use async_trait::async_trait;
use equs_sdk::http::{HttpClient, Result};
use oauth2::http::StatusCode;
use oauth2::{HttpRequest, HttpResponse};
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;

type HandlerFunc = dyn Fn(HttpRequest) -> Result<HttpResponse> + Sync + Send;

pub struct HttpClientEmulator {
    handlers: HashMap<Url, Box<HandlerFunc>>,
}

impl HttpClientEmulator {
    pub fn new() -> Self {
        HttpClientEmulator {
            handlers: HashMap::new(),
        }
    }

    pub fn add_handler(&mut self, url: Url, handler: Box<HandlerFunc>) {
        self.handlers.insert(url, handler);
    }
}

#[async_trait]
impl HttpClient for HttpClientEmulator {
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse> {
        if let Some(handler) = self
            .handlers
            .get(&Url::from_str(&request.uri().to_string()).unwrap())
        {
            return handler(request);
        }
        let mut resp = HttpResponse::new(vec![]);
        *resp.status_mut() = StatusCode::NOT_FOUND;

        Ok(resp)
    }
}
