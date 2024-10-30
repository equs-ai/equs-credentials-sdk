use crate::kms::Error as KmsError;
use crate::vc::presentation_exchange;
use crate::{http, nonce, vc};
use common_macros::DebugError;
use snafu::{Location, Snafu};
use std::fmt::Debug;

/// An `oid4vp` internal error.
///
/// Internal errors unspecified by the protocol.
///
/// Should be treated like 5xx errors.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum InternalError {
    #[snafu(display("Authorization Response error"))]
    AuthorizationResponse {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("Credential of Type '{type_}' and Format '{format}' not found"))]
    CredentialNotFound { type_: String, format: String },
    #[snafu(display("Unsupported format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("KMS error"))]
    KMS {
        #[snafu(implicit)]
        location: Location,
        source: KmsError,
    },
    #[snafu(display("oid4vp-rs library internal error"))]
    Oid4VpLib {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("JWS error"))]
    JWS {
        source: ssi::jws::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Parse error"))]
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
    #[snafu(display("VC error"))]
    VC {
        #[snafu(implicit)]
        location: Location,
        source: vc::core::Error,
    },
    #[snafu(display("Url parse error"))]
    UrlParse {
        #[snafu(implicit)]
        location: Location,
        source: url::ParseError,
    },
    #[snafu(display("Presentation exchange error"))]
    PresentationExchange {
        #[snafu(implicit)]
        location: Location,
        source: presentation_exchange::Error,
    },
    #[snafu(display("Http error"))]
    HttpClient {
        #[snafu(implicit)]
        location: Location,
        source: http::HttpError,
    },
    #[snafu(display("Nonce generation error"))]
    NonceGeneration {
        #[snafu(implicit)]
        location: Location,
        source: nonce::Error,
    },
}
