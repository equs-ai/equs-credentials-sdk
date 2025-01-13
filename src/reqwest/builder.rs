use reqwest::redirect::Policy;
use reqwest::Client;
use reqwest_tracing::TracingMiddleware;
use tracing::{instrument, Level};

use super::ReqwestClient;
use crate::http::{HttpSnafu, Result};
use crate::reqwest::middleware::ValidatorMiddleware;
use crate::reqwest::validators::content_size::ContentSizeLimiter;
use crate::reqwest::validators::content_type::ContentTypeValidator;

pub type Certificate = reqwest::Certificate;

#[derive(Debug)]
pub struct ReqwestClientBuilder {
    content_size_limiter: ContentSizeLimiter,
    insecure: bool,
    trusted_root_certs: Vec<Certificate>,
}

impl ReqwestClientBuilder {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new() -> Self {
        Self {
            content_size_limiter: ContentSizeLimiter::unlimited(),
            insecure: false,
            trusted_root_certs: vec![],
        }
    }

    /// Set limits for HTTP response body size.
    ///
    /// In case response body size is bigger that limit the `async_call()` method
    /// will return an error
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_sdk::reqwest::builder::ReqwestClientBuilder;
    /// use agent_sdk::reqwest::validators::content_size::ContentSizeLimiter;
    ///
    /// let client = ReqwestClientBuilder::new()
    ///     .with_response_content_size_limit(102400)
    ///     .build();
    /// ```
    #[instrument(level = Level::TRACE, ret())]
    pub fn with_response_content_size_limit(mut self, response_size_limit: usize) -> Self {
        self.content_size_limiter = self
            .content_size_limiter
            .with_response_size_limit(response_size_limit);
        self
    }

    /// Set limits for HTTP request body size.
    ///
    /// In case request body size is bigger than limit log entry with level `WARN`
    /// will be produced.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_sdk::reqwest::builder::ReqwestClientBuilder;
    /// use agent_sdk::reqwest::validators::content_size::ContentSizeLimiter;
    ///
    /// let client = ReqwestClientBuilder::new()
    ///     .with_request_content_size_limit(102400)
    ///     .build();
    /// ```
    #[instrument(level = Level::TRACE, ret())]
    pub fn with_request_content_size_limit(mut self, request_size_limit: usize) -> Self {
        self.content_size_limiter = self
            .content_size_limiter
            .with_request_size_limit(request_size_limit);
        self
    }

    /// Adds a trusted root certificate.
    ///
    /// This can be used to connect to a server that has a self-signed
    /// certificate for example.
    ///
    /// # Arguments
    ///
    /// * `cert` - A `Certificate` the trusted root certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use agent_sdk::reqwest::builder::{ Certificate, ReqwestClientBuilder };
    ///
    /// let cert = Certificate::from_pem("-----BEGIN CERTIFICATE-----...".as_bytes()).unwrap();
    /// let builder = ReqwestClientBuilder::new()
    ///     .add_trusted_root_certificate(cert)
    ///     .build();
    /// ```
    #[cfg(debug_assertions)]
    #[instrument(level = Level::TRACE, ret())]
    pub fn add_trusted_root_certificate(mut self, cert: Certificate) -> Self {
        self.trusted_root_certs.push(cert);
        self
    }

    /// Enables the HTTP client to make insecure `http` calls.
    ///
    /// This method configures the HTTP client to allow connections over the non-secure
    /// `http` protocol. This option can be used for testing or in environments where security is not a concern.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_sdk::reqwest::builder::ReqwestClientBuilder;
    ///
    /// let client = ReqwestClientBuilder::new()
    ///     .insecure()
    ///     .build();
    /// ```
    ///
    /// # Returns
    ///
    /// Returns an instance of `Self` with the `insecure` option enabled.
    ///
    #[cfg(debug_assertions)]
    #[instrument(level = Level::TRACE, ret())]
    pub fn insecure(mut self) -> Self {
        self.insecure = true;
        self
    }

    /// Builds and configures a `ReqwestClient` instance.
    ///
    /// This method creates a `reqwest::Client` based on the configuration specified by the builder.
    /// It supports both secure (`https`) and insecure (`http`) connections, depending on the builder's settings.
    /// Additionally, it applies middleware for content size limiting, content type validation, and tracing.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the configured `ReqwestClient` instance.
    /// In case of an error during the client creation, it returns an appropriate error.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_sdk::reqwest::builder::ReqwestClientBuilder;
    ///
    /// let client = ReqwestClientBuilder::new()
    ///     .with_response_content_size_limit(102400) // Sets the limit to response content size
    ///     .build();
    ///
    /// match client {
    ///     Ok(client) => println!("Client created successfully"),
    ///     Err(e) => println!("Failed to create client: {}", e),
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// * [crate::http::HttpError] - fails to build client.
    #[instrument(level = Level::TRACE, ret())]
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
            let mut builder = Client::builder()
                .https_only(true)
                .use_rustls_tls()
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .redirect(Policy::none());

            for cert in self.trusted_root_certs {
                builder = builder.add_root_certificate(cert)
            }

            builder.build().map_err(|err| {
                HttpSnafu {
                    details: err.to_string(),
                }
                .build()
            })?
        };

        let client_with_middleware = reqwest_middleware::ClientBuilder::new(client)
            .with(ValidatorMiddleware::new(
                self.content_size_limiter,
                ContentTypeValidator,
            ))
            .with(TracingMiddleware::default())
            .build();

        Ok(ReqwestClient {
            client: client_with_middleware,
        })
    }
}
