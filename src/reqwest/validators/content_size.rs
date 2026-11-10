use super::{ContentSizeSnafu, Result};
use futures::StreamExt;
use reqwest::Response;
use tracing::{Level, instrument};

/// `ContentLimiter` struct represents limitations of request/response body size.
#[derive(Clone, Debug)]
pub struct ContentSizeLimiter {
    pub(crate) req_size_limit: Option<usize>,
    pub(crate) resp_size_limit: Option<usize>,
}

impl ContentSizeLimiter {
    /// Creates an `ContentSizeLimiter` structure to limit the response body size in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use equs_sdk::reqwest::validators::content_size::ContentSizeLimiter;
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
    /// use equs_sdk::reqwest::validators::content_size::ContentSizeLimiter;
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
    /// use equs_sdk::reqwest::validators::content_size::ContentSizeLimiter;
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

    /// Reads the body chunk by chunk and fails at the first chunk over the response size limit.
    /// The buffer is never sized from `Content-Length`, which the server controls.
    pub(crate) async fn read_response_body(&self, response: Response) -> Result<Vec<u8>> {
        let mut chunks = std::pin::pin!(response.bytes_stream());
        let mut body = Vec::new();

        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.map_err(|e| {
                ContentSizeSnafu {
                    details: format!("cannot read response body: {e}"),
                }
                .build()
            })?;
            if self.is_resp_body_out_of_limit(body.len() + chunk.len()) {
                return ContentSizeSnafu {
                    details: "response body size exceeds the limit",
                }
                .fail();
            }
            body.extend_from_slice(&chunk);
        }

        Ok(body)
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use rstest::rstest;
    use std::io;

    #[test]
    fn unlimited_initializes_both_limits_to_none() {
        let l = ContentSizeLimiter::unlimited();

        assert_eq!(l.req_size_limit, None);
        assert_eq!(l.resp_size_limit, None);
    }

    #[test]
    fn with_response_size_limit_sets_resp_only() {
        let l = ContentSizeLimiter::unlimited().with_response_size_limit(1024);

        assert_eq!(l.resp_size_limit, Some(1024));
        assert_eq!(l.req_size_limit, None);
    }

    #[test]
    fn with_request_size_limit_sets_req_only() {
        let l = ContentSizeLimiter::unlimited().with_request_size_limit(2048);

        assert_eq!(l.req_size_limit, Some(2048));
        assert_eq!(l.resp_size_limit, None);
    }

    #[test]
    fn chained_builder_calls_set_both_limits() {
        let l = ContentSizeLimiter::unlimited()
            .with_request_size_limit(100)
            .with_response_size_limit(200);

        assert_eq!(l.req_size_limit, Some(100));
        assert_eq!(l.resp_size_limit, Some(200));
    }

    #[test]
    fn with_response_size_limit_preserves_previously_set_request_limit() {
        let l = ContentSizeLimiter::unlimited()
            .with_request_size_limit(50)
            .with_response_size_limit(500);

        assert_eq!(l.req_size_limit, Some(50));
        assert_eq!(l.resp_size_limit, Some(500));
    }

    #[rstest]
    #[case::unlimited_under(ContentSizeLimiter::unlimited(), 5_000, false)]
    #[case::unlimited_huge(ContentSizeLimiter::unlimited(), usize::MAX, false)]
    #[case::under_limit(
        ContentSizeLimiter::unlimited().with_request_size_limit(1024),
        512,
        false,
    )]
    #[case::at_boundary(
        ContentSizeLimiter::unlimited().with_request_size_limit(1024),
        1024,
        false,
    )]
    #[case::over_limit(
        ContentSizeLimiter::unlimited().with_request_size_limit(1024),
        2048,
        true,
    )]
    fn is_req_body_out_of_limit_evaluates_threshold(
        #[case] limiter: ContentSizeLimiter,
        #[case] body_size: usize,
        #[case] expected: bool,
    ) {
        assert_eq!(limiter.is_req_body_out_of_limit(body_size), expected);
    }

    #[tokio::test]
    async fn read_response_body_joins_chunks_within_the_limit() {
        let limiter = ContentSizeLimiter::unlimited().with_response_size_limit(10);
        let response = chunked_response(vec![Ok("hello"), Ok("world")]);

        let body = limiter.read_response_body(response).await.unwrap();

        assert_eq!(body, b"helloworld");
    }

    #[tokio::test]
    async fn read_response_body_stops_reading_past_the_limit() {
        let limiter = ContentSizeLimiter::unlimited().with_response_size_limit(10);
        let response = chunked_response(vec![
            Ok("hello"),
            Ok("world!"),
            Err(io::Error::other("read past the limit")),
        ]);

        let err = limiter.read_response_body(response).await.unwrap_err();

        assert!(err.to_string().contains("exceeds the limit"), "{err}");
    }

    #[tokio::test]
    async fn read_response_body_fails_on_a_read_error() {
        let limiter = ContentSizeLimiter::unlimited();
        let response = chunked_response(vec![Ok("hello"), Err(io::Error::other("reset"))]);

        let err = limiter.read_response_body(response).await.unwrap_err();

        assert!(
            err.to_string().contains("cannot read response body"),
            "{err}"
        );
    }

    /// A response whose body arrives as `chunks`, without `Content-Length`.
    fn chunked_response(chunks: Vec<io::Result<&'static str>>) -> Response {
        let body = reqwest::Body::wrap_stream(stream::iter(chunks));
        oauth2::http::Response::new(body).into()
    }
}
