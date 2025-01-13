use crate::reqwest::validators::content_size::ContentSizeLimiter;
use crate::reqwest::validators::content_type::ContentTypeValidator;
use oauth2::http;
use oauth2::http::Extensions;
use reqwest::header::SET_COOKIE;
use reqwest::{Request, Response};
use reqwest_middleware::{Error, Next, Result};
use tracing::warn;

pub struct ValidatorMiddleware {
    content_size_limiter: ContentSizeLimiter,
    content_type_validator: ContentTypeValidator,
}

impl ValidatorMiddleware {
    pub fn new(
        content_size_limiter: ContentSizeLimiter,
        content_type_validator: ContentTypeValidator,
    ) -> Self {
        Self {
            content_size_limiter,
            content_type_validator,
        }
    }
}

#[async_trait::async_trait]
impl reqwest_middleware::Middleware for ValidatorMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        if let Some(request_body_size) = req
            .body()
            .map(|body| body.as_bytes().map(|b| b.len()))
            .unwrap_or_default()
        {
            if self
                .content_size_limiter
                .is_req_body_out_of_limit(request_body_size)
            {
                warn!(
                    "Request body size is out of limit: request body size = {}",
                    request_body_size
                );
            }
        }

        let content_type_to_accept = self
            .content_type_validator
            .resolve_request_content_type(req.headers())
            .map_err(Error::middleware)?;
        // Run the request
        let mut outcome = next.run(req, extensions).await;

        if let Ok(response) = outcome.as_mut() {
            self.content_size_limiter
                .validate_content_length_header(response)
                .map_err(Error::middleware)?;
            let body = self
                .content_size_limiter
                .limit_response_body(response)
                .await
                .map_err(Error::middleware)?;

            self.content_type_validator
                .validate_response_content_type(
                    &content_type_to_accept,
                    response.headers(),
                    body.as_slice(),
                )
                .await
                .map_err(Error::middleware)?;

            let resp = sanitize_response(response, body);

            return Ok(resp);
        }

        outcome
    }
}

fn sanitize_response(response: &mut Response, body: Vec<u8>) -> Response {
    let mut resp = http::Response::new(body);
    *resp.status_mut() = response.status();
    *resp.headers_mut() = response.headers().to_owned();

    let cookie = resp.headers_mut().remove(SET_COOKIE);
    if let Some(cookie) = cookie {
        warn!(
            "set-cookie header with value = '{}' is removed",
            cookie.to_str().unwrap_or_default()
        )
    };

    resp.into()
}
