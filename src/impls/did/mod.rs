use async_trait::async_trait;
use ssi::did::{DIDMethods, Resource, VerificationMethod};
use ssi::did_resolve::{Content, dereference, DereferencingInputMetadata, DIDResolver as SpruceResolver};

use crate::core_::did::{DID, DIDResolver, Error, Resolution, ResolveOptions, VerificationMethodMap};

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

#[async_trait]
impl DIDResolver for UniversalResolver {
    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Resolution {
        let (metadata, doc, doc_metadata) = self.impls.resolve(did, &options.input).await;
        Resolution { doc, metadata, doc_metadata }
    }

    async fn resolve_verification_method(&self, did_url: &str) -> Result<VerificationMethodMap, Error> {
        resolve_verification_method(self.impls.to_resolver(), did_url).await
    }

    fn as_spruce_resolver(&self) -> &dyn SpruceResolver {
        self.impls.to_resolver()
    }
}

async fn resolve_verification_method(resolver: &dyn SpruceResolver, did_url: &str) -> Result<VerificationMethodMap, Error> {
    let (_, content, _) = dereference(resolver, did_url, &DereferencingInputMetadata::default()).await;

    let vm = match content {
        Content::Object(Resource::VerificationMethod(vm)) => Ok(vm),
        Content::DIDDocument(document) => {
            if let VerificationMethod::Map(vm) =
                document.verification_method.unwrap().first().unwrap()
            {
                Ok(vm.to_owned())
            } else {
                Err(Error::DereferencingError("could not find any verification method".into()))
            }
        }

        _ => Err(Error::DereferencingError("could not find specified verification method".into(),
        )),
    };
    vm
}