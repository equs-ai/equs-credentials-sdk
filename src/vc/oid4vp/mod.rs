//! OID4VP Spec implementation.

pub(crate) mod api;
#[cfg(feature = "delegate-sd-jwt")]
pub(crate) mod delegate;
pub(crate) mod holder;
pub(super) mod signer;
pub(crate) mod verifier;

mod builder;
mod internal_error;

pub mod jwe;
mod jwe_utils;
mod metadata;
mod protocol_error;
#[cfg(test)]
mod tests;

pub use builder::Error as BuilderError;
pub use builder::HolderBuilder;
pub use builder::VerifierBuilder;
pub use internal_error::InternalError;
pub use protocol_error::ErrorType;
pub use protocol_error::ProtocolError;

pub use api::*;

// Re-export the delegate wire types so external consumers can actually build the
// public `DelegationRequest` (its `format` field) and inspect `delegate`
// transaction-data items. Gated with the rest of the experimental feature.
#[cfg(feature = "delegate-sd-jwt")]
pub use delegate::{
    CLAIM_DELEGATE_PAYLOAD, DelegateSdJwtTransactionDataFormat, FORMAT_DSD_JWT, FORMAT_DSD_JWT_KB,
    TRANSACTION_TYPE_DELEGATE,
};
