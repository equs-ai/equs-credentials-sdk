//! Revocation Status List APIs.

use crate::crypto::Signer;
use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::vc::claims::Claims;
use async_trait::async_trait;
use common_macros::DebugError;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use ssi::dids::DIDURL;
use strum_macros::Display;

pub mod status_list_token_jwt;

/// `Status List` format internal error.
///
/// Defines errors for all supported low-level Status List operations.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Could not fetch status list: {details}"))]
    StatusListFetching { details: String },

    #[snafu(display("Status list creating failed: {details}"))]
    StatusListCreating { details: String },

    #[snafu(display("Signing error: {details}"))]
    Signing {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Claims error"))]
    Claims {
        source: crate::vc::claims::Error,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Parse error"))]
    Parse {
        #[snafu(implicit)]
        location: Location,
        source: serde_json::Error,
    },

    #[snafu(display("Malformed status list: {details}"))]
    MalformedStatusList { details: String },

    #[snafu(display("Could not get VC status: {details}"))]
    VCStatus { details: String },
}

/// `Result` alias for `Status List` API [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// Supported formats for status list tokens
#[derive(Debug, Display, PartialEq, Clone, Serialize, Deserialize)]
pub enum StatusListFormat {
    StatusListTokenJwt(status_list_token_jwt::SLMetadata),
    StatusListTokenCwt,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait API<CS, ST, SL, MD> {
    async fn create_status_list<S>(
        statuses: ST,
        issuer_data: (&DIDURL, S),
        metadata: &MD,
    ) -> Result<SL>
    where
        S: Signer;

    async fn get_vc_status(
        vc_claims: &Claims,
        http_client: &dyn HttpClient,
        did_resolver: UniversalResolver,
    ) -> Result<Option<CS>>;
}
