use crate::http::HttpError;
use crate::vc::oid4vci::metadata;
use crate::{nonce, storage, vault, vc};
use common_macros::DebugError;
use oid4vci::credential::RequestError;
use snafu::{Location, Snafu};
use std::fmt::Debug;

/// An `oid4vci` internal error.
///
/// Internal errors unspecified by the protocol.
///
/// Should be treated like 5xx errors.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
#[non_exhaustive]
pub enum InternalError {
    #[snafu(display("Credential definition not found for ID: {id}"))]
    CredDefNotFound {
        id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "No scope set for Credential definition ID: {id}. Only scope authorization supported"
    ))]
    NoScopeSet {
        id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Claims validation error: {details}"))]
    ClaimsValidation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Issuer service error: {details}"))]
    IssuerService {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Holder service error: {details}"))]
    HolderService {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Url parse error"))]
    UrlParse {
        #[snafu(implicit)]
        location: Location,
        source: url::ParseError,
    },
    #[snafu(display("Parse error"))]
    Parse {
        #[snafu(implicit)]
        location: Location,
        source: serde_json::Error,
    },
    #[snafu(display("Storage error"))]
    Storage {
        #[snafu(implicit)]
        location: Location,
        source: storage::Error,
    },
    #[snafu(display("VC error"))]
    VC {
        #[snafu(implicit)]
        location: Location,
        source: vc::core::Error,
    },
    #[snafu(display("Vault error"))]
    Vault {
        #[snafu(implicit)]
        location: Location,
        source: vault::Error,
    },
    #[snafu(display("Request error"))]
    Request {
        #[snafu(implicit)]
        location: Location,
        source: RequestError<HttpError>,
    },
    #[snafu(display("Discovery error"))]
    Discovery {
        #[snafu(implicit)]
        location: Location,
        //TODO: Check that nothing other than 'reqwest::Error' can be used here.
        source: anyhow::Error,
    },
    #[snafu(display("Http error"))]
    HttpClient {
        #[snafu(implicit)]
        location: Location,
        source: HttpError,
    },
    #[snafu(display("Metadata resolving error"))]
    Metadata {
        #[snafu(implicit)]
        location: Location,
        source: metadata::Error,
    },
    #[snafu(display("Nonce Handler error"))]
    NonceHandler {
        #[snafu(implicit)]
        location: Location,
        source: nonce::Error,
    },

    #[snafu(display("Type conversion error: {details}"))]
    TypeConversion {
        #[snafu(implicit)]
        location: Location,
        details: String,
    },
    #[snafu(display("authorization callback error: {details}"))]
    AuthorizationCallback {
        #[snafu(implicit)]
        location: Location,
        details: String,
    },
}
