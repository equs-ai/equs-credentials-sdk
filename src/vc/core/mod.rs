//! SSI Core module

pub(crate) mod api;
mod holder;
mod issuer;
pub mod status_issuer;
mod verifier;

#[cfg(test)]
pub(crate) mod tests;

pub use super::pop::Format as PopFormat;
pub use holder::HolderService;
pub use issuer::IssuerService;
pub use verifier::{VerificationParams, VerifierService};

pub use api::*;

pub const DEFAULT_CRED_LIFETIME_DAYS: i64 = 5 * 365;
pub const DEFAULT_POP_LIFETIME_MINUTES: i64 = 5;
