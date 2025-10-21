//! OID4VCi Spec implementation.

pub(crate) mod api;
pub(crate) mod holder;
pub(crate) mod issuer;
mod metadata;
mod token_validation;

mod builder;
mod internal_error;
mod protocol_error;

pub(crate) mod credential_issuer_identifier;
mod credential_offer_resolver;
#[cfg(test)]
pub(crate) mod tests;

pub use builder::Error as BuilderError;
pub use builder::HolderBuilder;
pub use builder::IssuerBuilder;
pub use builder::IssuerDiscovery;
pub use credential_offer_resolver::CredentialOfferResolver;
pub use credential_offer_resolver::Error as CredentialOfferResolverError;
pub use internal_error::InternalError;
pub use protocol_error::CredentialEndpointError as ProtocolErrorCredentialEndpoint;
pub use protocol_error::CredentialOfferEndpointError as ProtocolErrorCredentialOfferEndpoint;
pub use protocol_error::ErrorType as ProtocolErrorType;
pub use protocol_error::ProtocolError;
pub use protocol_error::TokenEndpointError as ProtocolErrorTokenEndpoint;

pub use api::*;
