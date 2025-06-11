use super::{ContentSizeSnafu, Result};
use reqwest::Response;
use tracing::{Level, instrument};

/// `ContentLimiter` struct represents limitations of request/response body size.
#[derive(Clone, Debug)]
pub struct ContentSizeLimiter {
    req_size_limit: Option<usize>,
    resp_size_limit: Option<usize>,
}

impl ContentSizeLimiter {
    /// Creates an `ContentSizeLimiter` structure to limit the response body size in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_sdk::reqwest::validators::content_size::ContentSizeLimiter;
    ///
    /// let limiter = ContentSizeLimiter::unlimited().with_response_size_limit(1024);
    ///
    /// ```
    #[instrument(level = Level::TRACE, ret())]
    pub fn with_response_size_limit(self, resp_size_limit: usize) -> Self {
        Self {
            req_size_limit: self.req_size_limit,
            resp_size_limit: Some(resp_size_limit),
        }
    }

    /// Creates an `ContentSizeLimiter` structure to limit the request body size in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_sdk::reqwest::validators::content_size::ContentSizeLimiter;
    ///
    /// let limiter = ContentSizeLimiter::unlimited().with_request_size_limit(1024);
    ///
    /// ```
    #[instrument(level = Level::TRACE, ret())]
    pub fn with_request_size_limit(self, req_size_limit: usize) -> Self {
        Self {
            resp_size_limit: self.resp_size_limit,
            req_size_limit: Some(req_size_limit),
        }
    }

    /// Creates an `ContentSizeLimiter` structure without any limits
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_sdk::reqwest::validators::content_size::ContentSizeLimiter;
    ///
    /// let unlimited = ContentSizeLimiter::unlimited();
    /// ```
    #[instrument(level = Level::TRACE, ret())]
    pub fn unlimited() -> Self {
        Self {
            req_size_limit: None,
            resp_size_limit: None,
        }
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    pub(crate) fn is_req_body_out_of_limit(&self, body_size: usize) -> bool {
        match self.req_size_limit {
            Some(limit) => body_size > limit,
            _ => false,
        }
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    fn is_resp_body_out_of_limit(&self, body_size: usize) -> bool {
        match self.resp_size_limit {
            Some(limit) => body_size > limit,
            _ => false,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(level = Level::TRACE, skip(self), ret(), err())]
    pub(crate) async fn limit_response_body(&self, response: &mut Response) -> Result<Vec<u8>> {
        let mut resp_body: Vec<u8> = match response.content_length() {
            Some(content_len) => Vec::with_capacity(content_len.try_into().unwrap_or_default()),
            None => Vec::new(),
        };

        while let Some(body_part) = response.chunk().await.map_err(|e| {
            ContentSizeSnafu {
                details: "cannot parse response body as a stream chunk",
            }
            .build()
        })? {
            // make sure that operation (resp_body.len() + body_part.len()) does not overflow
            if (usize::MAX - resp_body.len()) < body_part.len() {
                return ContentSizeSnafu {
                    details: "response body size exceeds usize::MAX value",
                }
                .fail();
            }

            let current_resp_size = resp_body.len() + body_part.len();

            if self.is_resp_body_out_of_limit(current_resp_size) {
                return ContentSizeSnafu {
                    details: "response body size exceeds the limit",
                }
                .fail();
            }

            resp_body.append(&mut body_part.to_vec());
        }

        Ok(resp_body)
    }

    #[instrument(level = Level::TRACE, skip(self), ret(), err())]
    pub(crate) fn validate_content_length_header(&self, response: &Response) -> Result<()> {
        let Some(content_len) = response.content_length() else {
            return Ok(());
        };

        let content_len: usize = content_len.try_into().map_err(|_| {
            ContentSizeSnafu {
                details: format!("content length value {} exceeds usize::MAX", content_len),
            }
            .build()
        })?;

        if self.is_resp_body_out_of_limit(content_len) {
            return ContentSizeSnafu {
                details: format!("content length value {} exceeds limit", content_len),
            }
            .fail();
        }

        Ok(())
    }
}
