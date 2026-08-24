use reqwest::Client;
use tracing::{Level, instrument};

use super::ReqwestClient;
use crate::http::{HttpSnafu, Result};
#[cfg(not(target_arch = "wasm32"))]
use crate::reqwest::middleware::ValidatorMiddleware;
use crate::reqwest::validators::content_size::ContentSizeLimiter;
use crate::reqwest::validators::content_type::ContentTypeValidator;

#[cfg(not(target_arch = "wasm32"))]
pub type Certificate = reqwest::Certificate;

#[cfg(target_arch = "wasm32")]
use crate::reqwest::WasmClient;

#[derive(Debug)]
pub struct ReqwestClientBuilder {
    content_size_limiter: ContentSizeLimiter,
    insecure: bool,
    #[cfg(not(target_arch = "wasm32"))]
    trusted_root_certs: Vec<Certificate>,
}

impl ReqwestClientBuilder {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new() -> Self {
        Self {
            content_size_limiter: ContentSizeLimiter::unlimited(),
            insecure: false,
            #[cfg(not(target_arch = "wasm32"))]
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
    /// use equs_sdk::reqwest::builder::ReqwestClientBuilder;
    /// use equs_sdk::reqwest::validators::content_size::ContentSizeLimiter;
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
    /// use equs_sdk::reqwest::builder::ReqwestClientBuilder;
    /// use equs_sdk::reqwest::validators::content_size::ContentSizeLimiter;
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
    /// use equs_sdk::reqwest::builder::{ Certificate, ReqwestClientBuilder };
    ///
    /// let cert = Certificate::from_pem("-----BEGIN CERTIFICATE-----...".as_bytes()).unwrap();
    /// let builder = ReqwestClientBuilder::new()
    ///     .add_trusted_root_certificate(cert)
    ///     .build();
    /// ```
    #[cfg(debug_assertions)]
    #[cfg(not(target_arch = "wasm32"))]
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
    /// use equs_sdk::reqwest::builder::ReqwestClientBuilder;
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
    /// use equs_sdk::reqwest::builder::ReqwestClientBuilder;
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
        #[cfg(target_arch = "wasm32")]
        {
            let client = Client::builder().build().map_err(|err| {
                HttpSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

            return Ok(ReqwestClient {
                wasm_client: WasmClient {
                    client,
                    content_size_limiter: self.content_size_limiter,
                    insecure: self.insecure,
                    content_type_validator: ContentTypeValidator,
                },
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            use reqwest::redirect::Policy;
            use reqwest_tracing::TracingMiddleware;

            let client = if self.insecure {
                Client::builder()
                    .https_only(false)
                    .danger_accept_invalid_certs(true)
                    .use_rustls_tls()
                    .tcp_keepalive(core::time::Duration::from_secs(60))
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
                    .tcp_keepalive(core::time::Duration::from_secs(60))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_initializes_defaults() {
        let b = ReqwestClientBuilder::new();

        // The default limiter is `unlimited()` — both req/resp size limits None.
        assert_eq!(b.content_size_limiter.req_size_limit, None);
        assert_eq!(b.content_size_limiter.resp_size_limit, None);
        assert!(!b.insecure);
        #[cfg(not(target_arch = "wasm32"))]
        assert!(b.trusted_root_certs.is_empty());
    }

    #[test]
    fn with_response_content_size_limit_propagates_to_inner_limiter() {
        let b = ReqwestClientBuilder::new().with_response_content_size_limit(4096);

        assert_eq!(b.content_size_limiter.resp_size_limit, Some(4096));
        assert_eq!(b.content_size_limiter.req_size_limit, None);
    }

    #[test]
    fn with_request_content_size_limit_propagates_to_inner_limiter() {
        let b = ReqwestClientBuilder::new().with_request_content_size_limit(8192);

        assert_eq!(b.content_size_limiter.req_size_limit, Some(8192));
        assert_eq!(b.content_size_limiter.resp_size_limit, None);
    }

    #[test]
    fn insecure_flag_is_set_on_builder() {
        let b = ReqwestClientBuilder::new().insecure();

        assert!(b.insecure);
    }

    #[test]
    fn chained_setters_compose_state() {
        let b = ReqwestClientBuilder::new()
            .insecure()
            .with_request_content_size_limit(100)
            .with_response_content_size_limit(200);

        assert!(b.insecure);
        assert_eq!(b.content_size_limiter.req_size_limit, Some(100));
        assert_eq!(b.content_size_limiter.resp_size_limit, Some(200));
    }

    #[test]
    fn build_succeeds_with_default_https_only_config() {
        // No insecure, no limits — the rustls/HTTPS-only branch must build cleanly.
        ReqwestClientBuilder::new().build().unwrap();
    }

    #[test]
    fn build_succeeds_with_insecure_branch() {
        ReqwestClientBuilder::new().insecure().build().unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn add_trusted_root_certificate_appends_to_internal_vec() {
        // A self-signed cert generated for testing only — PEM body validates
        // shape; we just need a parseable Certificate.
        const PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw\n\
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow\n\
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d\n\
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B\n\
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr\n\
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1\n\
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l\n\
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc\n\
6MF9+Yw1Yy0t\n\
-----END CERTIFICATE-----";

        let cert = Certificate::from_pem(PEM.as_bytes()).unwrap();

        let b = ReqwestClientBuilder::new().add_trusted_root_certificate(cert);

        assert_eq!(b.trusted_root_certs.len(), 1);
    }
}
