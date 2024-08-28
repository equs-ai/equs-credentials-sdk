use async_trait::async_trait;
use ssi::did::{Resource, VerificationMethod};
use ssi::did::did_resolve::DIDResolver as SpruceResolver;
use ssi::did_resolve::{Content, dereference, DereferencingInputMetadata};
use strum_macros::IntoStaticStr;

pub mod didkey;
pub mod universal;

// Error handling
#[derive(Debug, thiserror::Error, IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("method not supported: {0}")]
    MethodNotSupported(String),
    #[error("key not supported")]
    KeyNotSupported,
    #[error("generation error: {0}")]
    GenerationError(String),
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

    async fn resolve_verification_method(&self, did_url: &str) -> Result<VerificationMethodMap, Error> {
        resolve_verification_method(self.as_spruce_resolver(), did_url).await
    }

    fn as_spruce_resolver(&self) -> &dyn SpruceResolver;
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