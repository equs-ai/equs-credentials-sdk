//! Token Status List JWT (`typ: statuslist+jwt`).
//!
//! Built through the SDK's own `StatusListJwt::create_status_list`, so the
//! deflated bitstring and the `status_list` claim are the production ones.

use equs_sdk::vc::presentation_exchange::StatusSize;
use equs_sdk::vc::status_formats::API as StatusFormatsAPI;
use equs_sdk::vc::status_formats::status_list_token_jwt::{
    SLMetadata, StatusListJwt, VCStatus, VCStatuses,
};

use crate::error::{Error, Result};
use crate::keys::FixtureKey;

/// Default URL a status list fixture is published at; also its `sub` claim.
pub const DEFAULT_STATUS_LIST_URL: &str = "https://issuer.example/status-list";

/// Builder for a status list token.
///
/// The token's `sub` is the status list URL, and a verifier rejects the token
/// when the URL it fetched from disagrees — so the URL is the load-bearing
/// setting here, not an expiry.
pub struct StatusListToken<'a> {
    issuer: &'a FixtureKey,
    url: String,
    statuses_nr: usize,
    status_size: u8,
    statuses: VCStatuses,
}

impl<'a> StatusListToken<'a> {
    /// Starts a status list signed by `issuer`, with every entry valid.
    #[must_use]
    pub fn builder(issuer: &'a FixtureKey) -> Self {
        Self {
            issuer,
            url: DEFAULT_STATUS_LIST_URL.to_string(),
            statuses_nr: 32,
            status_size: 1,
            statuses: VCStatuses::new(),
        }
    }

    /// Sets the URL the list is published at, which becomes `sub`.
    #[must_use]
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    /// Sets how many entries the list holds.
    #[must_use]
    pub fn statuses_nr(mut self, statuses_nr: usize) -> Self {
        self.statuses_nr = statuses_nr;
        self
    }

    /// Sets the bit width per entry: 1, 2, 4 or 8.
    #[must_use]
    pub fn status_size(mut self, status_size: u8) -> Self {
        self.status_size = status_size;
        self
    }

    /// Marks `index` with `status`. Unset entries stay [`VCStatus::Valid`].
    #[must_use]
    pub fn status(mut self, index: usize, status: VCStatus) -> Self {
        self.statuses.set(index, status);
        self
    }

    /// Signs the status list and returns the compact token.
    ///
    /// # Errors
    ///
    /// * [`Error::Sdk`] — the URL is not a URL, the bit width is not 1/2/4/8, an
    ///   index overflows the list, or signing failed.
    pub async fn build(self) -> Result<String> {
        let metadata = SLMetadata {
            statuses_nr: self.statuses_nr,
            status_list_url: self.url.parse().map_err(|e| Error::Sdk {
                details: format!("status list url: {e}"),
            })?,
            status_size: StatusSize::try_from(self.status_size).map_err(|e| Error::Sdk {
                details: format!("status size: {e:?}"),
            })?,
        };

        StatusListJwt::create_status_list(
            self.statuses,
            (&self.issuer.did_url, self.issuer.handle.clone()),
            &metadata,
        )
        .await
        .map_err(|e| Error::Sdk {
            details: e.to_string(),
        })
    }
}
