//! OID4VP Spec implementation.

pub(crate) mod api;
pub(crate) mod holder;
pub(super) mod signer;
pub(crate) mod verifier;

mod builder;
mod internal_error;
mod metadata;
mod protocol_error;
#[cfg(test)]
mod tests;

pub use builder::Error as BuilderError;
pub use builder::HolderBuilder;
pub use builder::VerifierBuilder;
pub use internal_error::InternalError;
pub use protocol_error::ProtocolError;

pub use api::*;
