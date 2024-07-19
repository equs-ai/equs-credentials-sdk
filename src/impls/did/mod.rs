use ssi::did::DIDMethods;
use ssi::did_resolve::DIDResolver as Resolver;

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