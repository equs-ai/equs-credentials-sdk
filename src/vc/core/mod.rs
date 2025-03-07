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
pub use verifier::VerifierService;

pub use api::*;
