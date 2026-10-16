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
use std::collections::HashMap;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_list_fetching_display_includes_details() {
        let e = StatusListFetchingSnafu {
            details: "timeout".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Could not fetch status list: timeout"));
    }

    #[test]
    fn status_list_creating_display_includes_details() {
        let e = StatusListCreatingSnafu {
            details: "encoding failed".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Status list creating failed: encoding failed"));
    }

    #[test]
    fn malformed_status_list_display_includes_details() {
        let e = MalformedStatusListSnafu {
            details: "unexpected length".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Malformed status list: unexpected length"));
    }

    #[test]
    fn vc_status_display_includes_details() {
        let e = VCStatusSnafu {
            details: "index out of range".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Could not get VC status: index out of range"));
    }

    #[test]
    fn signing_display_includes_details() {
        let e = SigningSnafu {
            details: "key not found".to_string(),
        }
        .build();
        assert!(format!("{e}").contains("Signing error: key not found"));
    }
}

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

    /// Retrieves the status of a Verifiable Credential (VC) with caching support.
    ///
    /// # Arguments
    ///
    /// * `vc_claims` - Reference to the claims of the Verifiable Credential
    /// * `http_client` - HTTP client implementation for making network requests
    /// * `did_resolver` - Universal resolver for DID resolution
    /// * `cached_urls_per_status_jwts` - Optional mutable reference to a HashMap for caching status JWT URLs
    ///
    /// # Returns
    ///
    /// A credential status on success.
    ///
    /// # Errors
    ///
    /// * [Error::StatusListFetching] - When the status list cannot be fetched from the remote location
    /// * [Error::Claims] - When there are issues processing the credential claims
    /// * [Error::Parse] - When the retrieved status list cannot be parsed
    /// * [Error::VCStatus] - When the credential status cannot be determined
    /// * [Error::MalformedStatusList] - When the retrieved status list has an invalid format
    async fn get_vc_status(
        vc_claims: &Claims,
        http_client: &dyn HttpClient,
        did_resolver: UniversalResolver,
        cached_urls_per_status_jwts: Option<&mut HashMap<String, String>>,
    ) -> Result<Option<CS>>;
}
