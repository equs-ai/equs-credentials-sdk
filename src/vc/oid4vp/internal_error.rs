use common_macros::DebugError;
use snafu::{Location, Snafu};
use std::fmt::Debug;

use crate::kms::Error as KmsError;
use crate::vc::presentation_exchange;
use crate::{http, nonce, vc};

/// An `oid4vp` internal error.
///
/// Internal errors unspecified by the protocol.
///
/// Should be treated like 5xx errors.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum InternalError {
    #[snafu(display("Authorization Response error at {location}"))]
    AuthorizationResponse {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("Credential of Type '{type_}' and Format '{format}' not found"))]
    CredentialNotFound { type_: String, format: String },
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("KMS error at {location}"))]
    KMS {
        #[snafu(implicit)]
        location: Location,
        source: KmsError,
    },
    #[snafu(display("oid4vp-rs library internal error at {location}"))]
    Oid4VpLib {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("JWS error at {location}"))]
    JWS {
        source: ssi::jws::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Parse error at {location}"))]
    Json {
        #[snafu(implicit)]
        location: Location,
        source: serde_json::Error,
    },
    #[snafu(display("Parse error: {details}"))]
    Parse {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("VC error at {location}"))]
    VC {
        #[snafu(implicit)]
        location: Location,
        source: vc::core::Error,
    },
    #[snafu(display("Url parse error at {location}"))]
    UrlParse {
        #[snafu(implicit)]
        location: Location,
        source: url::ParseError,
    },
    #[snafu(display("Presentation exchange error at {location}"))]
    PresentationExchange {
        #[snafu(implicit)]
        location: Location,
        source: presentation_exchange::Error,
    },
    #[snafu(display("Http error at {location}"))]
    HttpClient {
        #[snafu(implicit)]
        location: Location,
        source: http::HttpError,
    },
    #[snafu(display("Nonce generation error at {location}"))]
    NonceGeneration {
        #[snafu(implicit)]
        location: Location,
        source: nonce::Error,
    },
}
