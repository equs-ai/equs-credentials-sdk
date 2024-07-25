use async_trait::async_trait;
use ssi::did::{DIDMethods, Document};
use ssi::did_resolve::{DIDResolver as Resolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata};

use crate::core_::did::{DID, DIDResolver, Resolution, ResolveOptions};

pub mod didkey;

pub struct UniversalResolver {
    impls: DIDMethods<'static>,
}

impl UniversalResolver {
    pub fn new() -> Self {
        let mut impls = DIDMethods::default();
        impls.insert(Box::new(did_method_key::DIDKey {}));

        Self { impls }
    }
}

impl DIDResolver for UniversalResolver {
    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Resolution {
        let (metadata, doc, _) = self.impls.resolve(did, &options.input).await;
        Resolution { doc, metadata }
    }
}

// for internal spruce usage
#[async_trait]
impl ssi::did::did_resolve::DIDResolver for UniversalResolver {
    async fn resolve(&self, did: &str, input_metadata: &ResolutionInputMetadata) -> (ResolutionMetadata, Option<Document>, Option<DocumentMetadata>) {
        self.impls.resolve(did, input_metadata).await
    }
}