use crate::http::HttpSnafu;
use crate::reqwest::validators::content_size::ContentSizeLimiter;
use crate::reqwest::validators::content_type::ContentTypeValidator;
use oauth2::{HttpRequest, HttpResponse};
use tracing::warn;

#[derive(Debug, Clone)]
pub struct WasmClient {
    pub client: reqwest::Client,
    pub content_size_limiter: ContentSizeLimiter,
    pub content_type_validator: ContentTypeValidator,
    pub insecure: bool,
}

impl WasmClient {
    pub async fn async_call(&self, request: HttpRequest) -> crate::http::Result<HttpResponse> {
        let (parts, body) = request.into_parts();

        if !self.insecure && parts.uri.scheme_str() != Some("https") {
            return Err(HttpSnafu {
                details: "Only HTTPS connections are allowed".to_string(),
            }
            .build());
        }

        let content_type_to_accept = self
            .content_type_validator
            .resolve_request_content_type(&parts.headers)
            .map_err(|err| {
                HttpSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        let body_size = body.len();
        if self
            .content_size_limiter
            .is_req_body_out_of_limit(body_size)
        {
            warn!(
                "Request body size is out of limit: request body size = {}",
                body_size
            );
        }

        let mut request_builder = self
            .client
            .request(parts.method, parts.uri.to_string())
            .body(body);

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

        self.content_size_limiter
            .validate_content_length_header(&response)?;

        let status_code = response.status();
        let headers = response.headers().to_owned();

        let chunks = response.bytes().await.map_err(|err| {
            HttpSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        self.content_type_validator
            .validate_response_content_type(&content_type_to_accept, &headers, &chunks)
            .await?;

        let resp_body = chunks.to_vec();
        let mut response = HttpResponse::new(resp_body);
        *response.status_mut() = status_code;
        *response.headers_mut() = headers;

        Ok(response)
    }
}
