use crate::reqwest::validators::content_size::ContentSizeLimiter;
use crate::reqwest::validators::content_type::ContentTypeValidator;
#[cfg(not(target_arch = "wasm32"))]
use reqwest::{Request, Response, StatusCode, header::HeaderMap};
#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl reqwest_middleware::Middleware for ValidatorMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut oauth2::http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        if let Some(request_body_size) = req
            .body()
            .map(|body| body.as_bytes().map(|b| b.len()))
            .unwrap_or_default()
            && self
                .content_size_limiter
                .is_req_body_out_of_limit(request_body_size)
        {
            warn!(
                "Request body size is out of limit: request body size = {}",
                request_body_size
            );
        }

        let content_type_to_accept = self
            .content_type_validator
            .resolve_request_content_type(req.headers())
            .map_err(reqwest_middleware::Error::middleware)?;
        let response = next.run(req, extensions).await?;

        self.content_size_limiter
            .validate_content_length_header(&response)
            .map_err(reqwest_middleware::Error::middleware)?;
        let status = response.status();
        let headers = response.headers().to_owned();
        let body = self
            .content_size_limiter
            .read_response_body(response)
            .await
            .map_err(reqwest_middleware::Error::middleware)?;

        self.content_type_validator
            .validate_response_content_type(&content_type_to_accept, &headers, body.as_slice())
            .await
            .map_err(reqwest_middleware::Error::middleware)?;

        Ok(sanitize_response(status, headers, body))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn sanitize_response(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Response {
    let mut resp = oauth2::http::Response::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;

    let cookie = resp.headers_mut().remove(reqwest::header::SET_COOKIE);
    if let Some(cookie) = cookie {
        warn!(
            "set-cookie header with value = '{}' is removed",
            cookie.to_str().unwrap_or_default()
        )
    };

    resp.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The `handle` method is exercised end-to-end through the mockito-based
    // integration tests in `reqwest/mod.rs`. The unit-isolated check here
    // verifies only that constructing the middleware does not require any
    // network or mock and that the wrapped components survive the move.
    #[test]
    fn new_constructs_middleware_with_provided_validators() {
        let limiter = ContentSizeLimiter::unlimited().with_response_size_limit(2048);
        let _ = ValidatorMiddleware::new(limiter, ContentTypeValidator);
    }
}
