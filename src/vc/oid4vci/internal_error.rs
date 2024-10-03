use crate::http::HttpError;
use crate::vc::oid4vci::metadata;
use crate::{nonce, storage, vault, vc};
use oid4vci::credential::RequestError;
use oid4vci::openidconnect::DiscoveryError;
use snafu::{Location, Snafu};
use std::fmt::Debug;

/// An `oid4vci` internal error.
///
/// Internal errors unspecified by the protocol.
///
/// Should be treated like 5xx errors.
#[derive(Snafu)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum InternalError {
    #[snafu(display("Credential definition not found for ID: {id}"))]
    CredDefNotFound { id: String },
    #[snafu(display(
        "No scope set for Credential definition ID: {id}. Only scope authorization supported"
    ))]
    NoScopeSet { id: String },
    #[snafu(display("Claims validation error at {location}\n Cause: {details}"))]
    ClaimsValidation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Issuer service error at {location}\n Cause: {details}"))]
    IssuerService {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Url parse error at {location}"))]
    UrlParse {
        #[snafu(implicit)]
        location: Location,
        source: url::ParseError,
    },
    #[snafu(display("Parse error at {location}"))]
    Parse {
        #[snafu(implicit)]
        location: Location,
        source: serde_json::Error,
    },
    #[snafu(display("Storage error at {location}"))]
    Storage {
        #[snafu(implicit)]
        location: Location,
        source: storage::Error,
    },
    #[snafu(display("VC error at {location}"))]
    VC {
        #[snafu(implicit)]
        location: Location,
        source: vc::core::Error,
    },
    #[snafu(display("Vault error at {location}"))]
    Vault {
        #[snafu(implicit)]
        location: Location,
        source: vault::Error,
    },
    #[snafu(display("Request error at {location}"))]
    Request {
        #[snafu(implicit)]
        location: Location,
        source: RequestError<HttpError>,
    },
    #[snafu(display("Discovery error at {location}"))]
    Discovery {
        #[snafu(implicit)]
        location: Location,
        //TODO: Check that nothing other than 'reqwest::Error' can be used here.
        source: DiscoveryError<HttpError>,
    },
    #[snafu(display("Http error at {location}"))]
    HttpClient {
        #[snafu(implicit)]
        location: Location,
        source: HttpError,
    },
    #[snafu(display("Metadata resolving error at {location}"))]
    Metadata {
        #[snafu(implicit)]
        location: Location,
        source: metadata::Error,
    },
    #[snafu(display("Nonce generation error at {location}"))]
    NonceGeneration {
        #[snafu(implicit)]
        location: Location,
        source: nonce::Error,
    },
}

impl Debug for InternalError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        let mut error: &dyn std::error::Error = self;
        while let Some(source) = error.source() {
            write!(fmt, "\n Cause: {}", source)?;
            error = source;
        }

        Ok(())
    }
}
