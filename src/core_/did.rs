use std::fmt;

// Error handling
#[derive(fmt::Debug)]
pub enum Error {
    MethodNotSupported(String),
    KeyNotSupported,
    GenerationError,
}

// Basic types definitions
pub type DID = String;
pub type DIDURL = ssi::did::DIDURL;
pub type DIDDoc = ssi::did::Document;
pub type ResolutionMetadata = ssi::did_resolve::ResolutionMetadata;
pub type ResolutionInputMetadata = ssi::did_resolve::ResolutionInputMetadata;

#[derive(Default)]
pub struct Resolution {
    pub metadata: ResolutionMetadata,
    pub doc: Option<DIDDoc>,
}

// Methods options
#[derive(Default)]
pub struct ResolveOptions {
    pub input: ResolutionInputMetadata,
}

pub trait DIDResolver {
    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Resolution;
}

