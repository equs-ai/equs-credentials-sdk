//! Error type shared by every fixture builder.
//!
//! Test fixtures fail loudly: no builder falls back to a default token when a
//! step fails, so a broken fixture surfaces as a failing test rather than as a
//! token that silently means something else.

use snafu::Snafu;

/// `Result` alias for the fixture [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Everything a fixture builder can fail on.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    /// Key creation or lookup in the KMS failed.
    #[snafu(display("kms: {details}"))]
    Kms {
        /// What failed, from the underlying error.
        details: String,
    },

    /// A `did:key` could not be generated or resolved.
    #[snafu(display("did: {details}"))]
    Did {
        /// What failed, from the underlying error.
        details: String,
    },

    /// The signer rejected the payload, or the key carries no JWK.
    #[snafu(display("signing: {details}"))]
    Signing {
        /// What failed, from the underlying error.
        details: String,
    },

    /// Claims or a header could not be rendered as JSON.
    #[snafu(display("json: {details}"))]
    Json {
        /// What failed, from the underlying error.
        details: String,
    },

    /// An SDK constructor rejected the fixture input.
    #[snafu(display("sdk: {details}"))]
    Sdk {
        /// What failed, from the underlying error.
        details: String,
    },
}
