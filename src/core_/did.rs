use async_trait::async_trait;
use ssi::did::did_resolve::DIDResolver as SpruceResolver;
use strum_macros::IntoStaticStr;

// Error handling
#[derive(Debug, thiserror::Error, IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("method not supported: {0}")]
    MethodNotSupported(String),
    #[error("key not supported")]
    KeyNotSupported,
    #[error("key not supported")]
    GenerationError,
    #[error("dereferencing error: {0}")]
    DereferencingError(String),
}

// Basic types definitions
pub type DID = String;
pub type DIDURL = ssi::did::DIDURL;
pub type DIDDoc = ssi::did::Document;
pub type DocumentMetadata = ssi::did_resolve::DocumentMetadata;
pub type VerificationMethodMap = ssi::did::VerificationMethodMap;
pub type ResolutionMetadata = ssi::did_resolve::ResolutionMetadata;
pub type ResolutionInputMetadata = ssi::did_resolve::ResolutionInputMetadata;

#[derive(Default, Clone)]
pub struct Resolution {
    pub metadata: ResolutionMetadata,
    pub doc: Option<DIDDoc>,
    pub doc_metadata: Option<DocumentMetadata>,
}

// Methods options
#[derive(Default, Clone)]
pub struct ResolveOptions {
    pub input: ResolutionInputMetadata,
}

#[async_trait]
pub trait DIDResolver: Send + Sync {
    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Resolution;

    async fn resolve_verification_method(&self, did_url: &str) -> Result<VerificationMethodMap, Error>;

    fn as_spruce_resolver(&self) -> &dyn SpruceResolver;
}