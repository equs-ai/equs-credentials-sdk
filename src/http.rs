//! APIs for implementing HTTP Client.

use async_trait::async_trait;
use common_macros::DebugError;
#[cfg(test)]
use mockall::automock;
use snafu::{Location, Snafu};
use std::fmt::Debug;

/// `HttpClient` Error.
///
/// All implementations of [HttpClient] should raise it on error.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[snafu(display("HTTP error: {details}"))]
pub struct HttpError {
    details: String,
    #[snafu(implicit)]
    location: Location,
}
pub use oauth2::http::{HeaderMap, HeaderName, HeaderValue, Method as HttpMethod, StatusCode, Uri};

pub use oauth2::{HttpRequest, HttpResponse};

/// `Result` alias for `HttpClient`-specific [HttpError].
pub type Result<T> = std::result::Result<T, HttpError>;

/// An async `HttpClient` interface used for internal Http(s) calls in the APIs.
///
/// Should be implemented by any adapter to be used with `Equs SDK`.
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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
}
