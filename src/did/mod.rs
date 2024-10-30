use async_trait::async_trait;
use common_macros::DebugError;
use snafu::{Location, Snafu};
use ssi::did::did_resolve::DIDResolver as SpruceResolver;
use ssi::did::{Resource, VerificationMethod};
use ssi::did_resolve::{dereference, Content, DereferencingInputMetadata};
use std::fmt::Debug;
use tracing::{instrument, Level};

pub mod didkey;
pub mod didweb;
pub mod universal;

/// `DID` Error.
///
/// Enumerates general errors expected during `DID` operations.
#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported method: {method}"))]
    MethodNotSupported { method: String },
    #[snafu(display("Unsupported key: {type_}"))]
    KeyNotSupported { type_: String },
    #[snafu(display("Invalid format of DID: {details}"))]
    InvalidDidFormat { details: String },
    #[snafu(display("DID generation error: {details}"))]
    DidGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("DID Document generation error: {details}"))]
    DidDocGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Resolution error: {details}"))]
    Resolution {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

/// `Result` alias for `DID`-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

// Basic types definitions
pub type DID = String;
pub type DIDURL = ssi::did::DIDURL;
pub type DIDDoc = ssi::did::Document;
pub type DocumentMetadata = ssi::did_resolve::DocumentMetadata;
pub type VerificationMethodMap = ssi::did::VerificationMethodMap;
pub type ResolutionMetadata = ssi::did_resolve::ResolutionMetadata;
pub type ResolutionInputMetadata = ssi::did_resolve::ResolutionInputMetadata;

/// A result of `DID` resolution.
///
/// Contains resolution metadata, resolved DID doc and the doc's metadata.
#[derive(Debug, Default, Clone)]
pub struct Resolution {
    pub metadata: ResolutionMetadata,
    pub doc: Option<DIDDoc>,
    pub doc_metadata: Option<DocumentMetadata>,
}

/// General options for `DID` resolution.
#[derive(Debug, Default, Clone)]
pub struct ResolveOptions {
    pub input: ResolutionInputMetadata,
}

/// A common async `DID` resolver trait.
///
/// Should be implemented by all supported `DID` methods.
#[async_trait]
pub trait DIDResolver: Send + Sync {
    /// Resolve `DID` document by the provided `DID`.
    ///
    /// # Arguments
    ///
    /// * `did` - a `DID` to resolve.
    /// * `options` - options for `DID` resolving.
    ///
    /// # Returns
    ///
    /// A `Resolution` struct containing `DID` doc and metadata or the error definition.
    async fn resolve(&self, did: &str, options: ResolveOptions) -> Resolution;

    /// A helper method to resolve `VerificationMethod` for the provided `DIDURL`.
    ///
    /// # Arguments
    ///
    /// * `did_url` - a `DIDURL` to resolve.
    ///
    /// # Returns
    ///
    /// A resolved `VerificationMethodMap` for the provided `DIDURL`
    /// containing the verification key and other parameters on success.
    ///
    /// # Errors
    ///
    /// * [Error::Resolution] - fails to revolve `DIDURL`.
    async fn resolve_verification_method(&self, did_url: &str) -> Result<VerificationMethodMap> {
        resolve_verification_method(self.as_spruce_resolver(), did_url).await
    }

    /// Coverts resolver to Spruce-compatible one.
    ///
    /// For internal usage.
    ///
    /// # Returns
    ///
    /// A resolver that implements [SpruceResolver] trait.
    fn as_spruce_resolver(&self) -> &dyn SpruceResolver;
}

#[instrument(
    level = Level::TRACE,
    skip(resolver),
    err(),
    ret(),
)]
async fn resolve_verification_method(
    resolver: &dyn SpruceResolver,
    did_url: &str,
) -> Result<VerificationMethodMap> {
    let (_, content, _) =
        dereference(resolver, did_url, &DereferencingInputMetadata::default()).await;

    match content {
        Content::Object(Resource::VerificationMethod(vm)) => Ok(vm),
        Content::DIDDocument(document) => {
            let vm_option = document
                .verification_method
                .as_ref()
                .and_then(|methods| methods.first())
                .ok_or_else(|| {
                    ResolutionSnafu {
                        details: format!(
                            "No verification method found in DID document for DID URL: {did_url}"
                        ),
                    }
                    .build()
                })?;

            if let VerificationMethod::Map(vm) = vm_option {
                Ok(vm.clone())
            } else {
                ResolutionSnafu {
                    details: format!(
                        "Could not find any verification method for DID URL: {did_url}"
                    ),
                }
                .fail()
            }
        }
        _ => ResolutionSnafu {
            details: format!("Failed to resolve verification method for DID URL: {did_url}"),
        }
        .fail(),
    }
}
