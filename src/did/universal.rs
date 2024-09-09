use async_trait::async_trait;
use ssi::did::DIDMethods;
use ssi::did_resolve::DIDResolver as SpruceResolver;
use tracing::{instrument, trace, Level};

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
    #[instrument(
        level = Level::TRACE,
    )]
    pub fn new() -> Self {
        let mut impls = DIDMethods::default();
        impls.insert(Box::new(did_method_key::DIDKey {}));

        Self { impls }
    }
}

#[async_trait]
impl DIDResolver for UniversalResolver {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(level = Level::TRACE)
    )]
    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Resolution {
        let (metadata, doc, doc_metadata) = self.impls.resolve(did, &options.input).await;

        trace!(resolved_metadata = ?metadata, resolved_did_doc = ?doc, resolved_did_doc_metadata = ?doc_metadata);

        Resolution {
            doc,
            metadata,
            doc_metadata,
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip_all,
    )]
    fn as_spruce_resolver(&self) -> &dyn SpruceResolver {
        self.impls.to_resolver()
    }
}
