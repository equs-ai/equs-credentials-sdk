use async_trait::async_trait;
use ssi::did::DIDMethods;
use ssi::did_resolve::DIDResolver as SpruceResolver;

use crate::did::{DIDResolver, Resolution, ResolveOptions, DID};

/// An Universal `DID` resolver.
///
/// # Supported methods
///
/// `did:key`
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

#[async_trait]
impl DIDResolver for UniversalResolver {
    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Resolution {
        let (metadata, doc, doc_metadata) = self.impls.resolve(did, &options.input).await;
        Resolution {
            doc,
            metadata,
            doc_metadata,
        }
    }

    fn as_spruce_resolver(&self) -> &dyn SpruceResolver {
        self.impls.to_resolver()
    }
}
