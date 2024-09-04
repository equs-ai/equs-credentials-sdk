use std::fmt::Debug;
use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use oauth2::{HttpRequest, HttpResponse};
use snafu::{Location, Snafu};

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

pub type Result<T> = std::result::Result<T, HttpError>;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait HttpClient: Sync + Send {
    async fn async_call(&self, request: HttpRequest) -> Result<HttpResponse>;

    async fn static_async(request: HttpRequest) -> Result<HttpResponse>
    where
        Self: Sized;
}
