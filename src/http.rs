use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use oauth2::{HttpRequest, HttpResponse};
use snafu::{Location, Snafu};
use std::fmt::Debug;

/// `HttpClient` Error.
///
/// All implementations of [HttpClient] should raise it on error.
#[derive(Snafu)]
#[snafu(visibility(pub))]
#[snafu(display("HTTP error at {location}\n Cause: {details}"))]
pub struct HttpError {
    details: String,
    #[snafu(implicit)]
    location: Location,
}

impl Debug for HttpError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;
        Ok(())
    }
}

/// `Result` alias for `HttpClient`-specific [HttpError].
pub type Result<T> = std::result::Result<T, HttpError>;

/// An async `HttpClient` interface used for internal Http(s) calls in the APIs.
///
/// Should be implemented by any adapter to be used with `ASDK`.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait HttpClient: Sync + Send {
    /// Make an async HTTP call.
    ///
    /// # Arguments
    ///
    /// * `request` - an HttpRequest.
    ///
    /// # Returns
    ///
    /// A successful HttpResponse on success.
    ///
    /// # Errors
    ///
    /// * [HttpError] - in case of failures and 4xx/5xx codes.
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse>;

    /// Make an async HTTP call (static).
    ///
    /// # Arguments
    ///
    /// * `request` - an HttpRequest.
    ///
    /// # Returns
    ///
    /// A successful HttpResponse on success.
    ///
    /// # Errors
    ///
    /// * [HttpError] - in case of failures and 4xx/5xx codes.
    ///
    /// *NOTE*: assumed to use standard implementation for a Client to make a call.
    async fn static_async(request: HttpRequest) -> Result<HttpResponse>
    where
        Self: Sized;
}
