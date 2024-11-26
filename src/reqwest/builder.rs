use super::{HttpLimits, ReqwestClient};
use crate::http::{HttpSnafu, Result};
use reqwest::redirect::Policy;
use reqwest::Client;
use tracing::{instrument, Level};

#[derive(Debug)]
pub struct ReqwestClientBuilder {
    limits: HttpLimits,
    insecure: bool,
}

impl ReqwestClientBuilder {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new() -> Self {
        Self {
            limits: HttpLimits::unlimited(),
            insecure: false,
        }
    }

    /// Set limits for HTTP request/response body size.
    ///
    /// In case request body size is bigger than limit log entry with level `WARN`
    /// will be produced.
    /// In case response body size is bigger that limit the `async_call()` method
    /// will return an error
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_sdk::reqwest::builder::ReqwestClientBuilder;
    /// use agent_sdk::reqwest::HttpLimits;
    ///
    /// let client = ReqwestClientBuilder::new()
    ///     .with_limits(HttpLimits::new(Some(102400), Some(102400)))
    ///     .build();
    /// ```
    #[instrument(level = Level::TRACE, ret())]
    pub fn with_limits(mut self, limits: HttpLimits) -> Self {
        self.limits = limits;
        self
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn insecure(mut self) -> Self {
        self.insecure = true;
        self
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    pub fn build(self) -> Result<ReqwestClient> {
        let client = if self.insecure {
            Client::builder()
                .https_only(false)
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|err| {
                    HttpSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?
        } else {
            Client::builder()
                .https_only(true)
                .use_rustls_tls()
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .redirect(Policy::none())
                .build()
                .map_err(|err| {
                    HttpSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?
        };

        Ok(ReqwestClient {
            client,
            limits: self.limits,
        })
    }
}
