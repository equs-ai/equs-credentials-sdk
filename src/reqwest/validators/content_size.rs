use super::{ContentSizeSnafu, HttpPayloadError, Result};
use futures::{Stream, StreamExt};
use reqwest::Response;
use tracing::{Level, instrument};

/// Upper bound on the response buffer allocated up front from a `Content-Length` header.
const MAX_PREALLOCATED_BODY_SIZE: usize = 64 * 1024;

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

    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(level = Level::TRACE, skip(self), ret(), err())]
    pub(crate) async fn limit_response_body(&self, response: &mut Response) -> Result<Vec<u8>> {
        let content_length = response.content_length();
        let body = futures::stream::unfold(response, |response| async move {
            let chunk = response.chunk().await.map_err(|_| {
                ContentSizeSnafu {
                    details: "cannot parse response body as a stream chunk",
                }
                .build()
            });
            chunk.transpose().map(|chunk| (chunk, response))
        });

        self.read_limited_body(body, content_length).await
    }

    /// Reads `body` chunk by chunk and stops at the first chunk that takes it over the response
    /// size limit, so a body without `Content-Length` cannot exceed the limit either.
    pub(crate) async fn read_limited_body<B, E>(
        &self,
        body: impl Stream<Item = std::result::Result<B, E>>,
        content_length: Option<u64>,
    ) -> std::result::Result<Vec<u8>, E>
    where
        B: AsRef<[u8]>,
        E: From<HttpPayloadError>,
    {
        // `Content-Length` is server-controlled: it may size the initial buffer, never beyond
        // `MAX_PREALLOCATED_BODY_SIZE`. The buffer grows as body bytes actually arrive.
        let capacity = content_length
            .and_then(|len| usize::try_from(len).ok())
            .map_or(0, |len| len.min(MAX_PREALLOCATED_BODY_SIZE));
        let mut resp_body: Vec<u8> = Vec::with_capacity(capacity);
        let mut body = std::pin::pin!(body);

        while let Some(body_part) = body.next().await {
            let body_part = body_part?;
            let body_part = body_part.as_ref();

            // make sure that operation (resp_body.len() + body_part.len()) does not overflow
            if (usize::MAX - resp_body.len()) < body_part.len() {
                return Err(ContentSizeSnafu {
                    details: "response body size exceeds usize::MAX value",
                }
                .build()
                .into());
            }

            let current_resp_size = resp_body.len() + body_part.len();

            if self.is_resp_body_out_of_limit(current_resp_size) {
                return Err(ContentSizeSnafu {
                    details: "response body size exceeds the limit",
                }
                .build()
                .into());
            }

            resp_body.extend_from_slice(body_part);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reqwest::validators::{ContentTypeSnafu, HttpPayloadError};
    use futures::stream;
    use rstest::rstest;

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
    async fn read_limited_body_joins_chunks_within_the_limit() {
        let limiter = ContentSizeLimiter::unlimited().with_response_size_limit(10);
        let body = stream::iter([
            Ok::<_, HttpPayloadError>(b"hello".to_vec()),
            Ok(b"world".to_vec()),
        ]);

        let read = limiter.read_limited_body(body, None).await.unwrap();

        assert_eq!(read, b"helloworld");
    }

    #[tokio::test]
    async fn read_limited_body_stops_reading_past_the_limit_without_content_length() {
        let limiter = ContentSizeLimiter::unlimited().with_response_size_limit(10);
        let body = stream::iter([
            Ok(b"hello".to_vec()),
            Ok(b"world!".to_vec()),
            Err(ContentTypeSnafu {
                details: "read past the limit",
            }
            .build()),
        ]);

        let err = limiter.read_limited_body(body, None).await.unwrap_err();

        assert!(
            matches!(&err, HttpPayloadError::ContentSize { details } if details == "response body size exceeds the limit"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn read_limited_body_returns_the_read_error() {
        let limiter = ContentSizeLimiter::unlimited();
        let body = stream::iter([
            Ok(b"hello".to_vec()),
            Err(ContentTypeSnafu {
                details: "connection reset",
            }
            .build()),
        ]);

        let err = limiter.read_limited_body(body, None).await.unwrap_err();

        assert!(
            matches!(&err, HttpPayloadError::ContentType { details } if details == "connection reset"),
            "{err}"
        );
    }
}
