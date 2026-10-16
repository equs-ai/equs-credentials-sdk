pub mod holder;
pub mod issuer;
pub mod signer;
pub mod status_formats;
pub mod status_issuer;
pub mod types;
pub mod verifier;

pub use holder::VCCoreHolder;
pub use issuer::VCCoreIssuer;
pub use status_formats::{SLMetadata, StatusListFormat};
pub use status_issuer::VCCoreStatusIssuer;
pub use types::{
    // Hand-written wrapper records / enums
    CredentialDefinition,
    // SDK remote-bridged types
    CredentialDefinitionData,
    CredentialOffer,
    CredentialOfferContent,
    CredentialOfferData,
    CredentialRequest,
    CredentialRequestData,
    CredentialStatusInfo,
    Display,
    HolderBinder,
    HolderMetadata,
    IssuerMetadata,
    IssuerMetadataData,
    PopFormat,
    Presentation,
    PresentationInput,
    PresentationRestriction,
    PresentationRestrictionValue,
    Proof,
    // FFI-boundary projections of SDK HashMap/usize keys
    StatusEntry,
    StatusIssuerMetadata,
    StatusList,
    StatusListDefinition,
    SupportedProofEntry,
    VCStatusesData,
};
pub use verifier::VCCoreVerifier;
