use crate::kms::Error as KmsError;
use crate::vc::claims::Error as ClaimsError;
use crate::vc::{dcql, presentation_exchange};
use crate::{http, nonce, vc};
use common_macros::DebugError;
use snafu::{Location, Snafu};
use ssi::dids::InvalidDIDURL;
use std::fmt::Debug;

/// An `oid4vp` internal error.
///
/// Internal errors unspecified by the protocol.
///
/// Should be treated like 5xx errors.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub(super)))]
pub enum InternalError {
    #[snafu(display("Authorization Response error"))]
    AuthorizationResponse {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("Authorization Response mode unsupported: {details}"))]
    AuthorizationResponseUnsupportedMode {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Authorization Response jwe decryption error: {details}"))]
    AuthorizationResponseDecryption {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Credential not found"))]
    CredentialNotFound,
    #[snafu(display("Please provide the metadata required to generate the ID token"))]
    IdTokenMetadataNotFound,
    #[snafu(display("ID token parse error"))]
    IdTokenParse {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
    #[snafu(display("ID token validation error: {details}"))]
    IdTokenValidation {
        #[snafu(implicit)]
        location: Location,
        details: String,
    },
    #[snafu(display("ID token generation error"))]
    IdTokenGeneration {
        #[snafu(implicit)]
        location: Location,
        source: anyhow::Error,
    },
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
        source: ssi::claims::jws::Error,
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
        source: vc::core::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("VC status error"))]
    VCStatus {
        source: vc::core::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("VC is not valid: {details}"))]
    VCNotValid { details: String },

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
    #[snafu(display("DCQL error"))]
    DCQL {
        #[snafu(implicit)]
        location: Location,
        source: dcql::Error,
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

    #[snafu(display("Claims error"))]
    Claims {
        source: ClaimsError,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("DID url buf resolution error"))]
    DidUrlResolution {
        source: InvalidDIDURL<String>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("JWE error: {details}"))]
    JWE {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Client ID"))]
    ClientId {
        source: anyhow::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Transaction data error: {details}"))]
    TransactionData {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}
