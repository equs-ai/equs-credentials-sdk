pub mod address;
pub mod block;
pub mod did_doc_attribute;
pub mod did_doc_builder;
pub mod did_events;
pub mod resolution;

pub use self::{
    address::Address,
    block::Block,
    did_doc_attribute::{
        DelegateType, DidDocAttribute, PublicKeyPurpose, ServiceAttribute, VerificationKeyType,
    },
    did_events::{DidAttributeChanged, DidDelegateChanged, DidEvents, DidOwnerChanged},
    resolution::{
        DID_RESOLUTION_FORMAT, DidDocumentWithMeta, DidMetadata, DidRecord, DidResolutionError,
        DidResolutionMetadata, DidResolutionOptions,
    },
};
