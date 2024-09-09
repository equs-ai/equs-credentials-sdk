use async_trait::async_trait;
use ssi::did::{DIDMethod, Source};
use ssi::did_resolve::DIDResolver as SpruceResolver;
use tracing::{instrument, trace, Level};

use crate::did::{
    DIDResolver, DidGenerationSnafu, KeyNotSupportedSnafu, Resolution, ResolveOptions, Result, DID,
};
use crate::{crypto, did};

pub type Error = did::Error;

/// A general `did:key` service.
///
/// Supports generation of `did:keys` and resolving (via common [DIDResolver]).
pub struct DIDKey {
    method: did_method_key::DIDKey,
}

impl DIDKey {
    #[instrument(
        level = Level::TRACE,
    )]
    pub fn new() -> Self {
        Self {
            method: did_method_key::DIDKey {},
        }
    }

    /// Create a `did:key`.
    ///
    /// # Arguments
    ///
    /// * `key` - a key to include in `did:key`.
    ///
    /// # Returns
    ///
    /// A new `did:key` based on the `key` on success.
    ///
    /// # Errors
    ///
    /// * [Error::KeyNotSupported] - fails if the `jwk` is not supported for `key`.
    /// * [Error::DidGeneration] - can't generate `DID`.
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(level = Level::TRACE)
    )]
    pub fn generate<K>(&self, key: K) -> Result<DID>
    where
        K: crypto::Key,
    {
        let jwk = key
            .jwk()
            .ok_or_else(|| KeyNotSupportedSnafu { type_: "jwk" }.build())?;

        let did = self.method.generate(&Source::Key(&jwk));
        did.ok_or_else(|| {
            DidGenerationSnafu {
                details: "did:key generation failed",
            }
            .build()
        })
    }
}

#[async_trait]
impl DIDResolver for DIDKey {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(level = Level::TRACE)
    )]
    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Resolution {
        let (metadata, doc, doc_metadata) =
            self.method.to_resolver().resolve(did, &options.input).await;

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
        self.method.to_resolver()
    }
}

#[cfg(test)]
mod tests {
    use ssi::did::VerificationMethod;

    use crate::crypto::Key;
    use crate::did::didkey::DIDKey;
    use crate::did::DIDResolver;
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::{CreateOptions, Kms};

    #[tokio::test]
    async fn e2e() {
        // Init
        let kms = LocalKms::new();
        let didkey = DIDKey::new();

        for kt in [kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Key
            let (_, kh) = kms.create_and_handle(kt, CreateOptions {}).await.unwrap();

            // Creation
            let did = didkey.generate(kh.clone()).unwrap();
            let jwk = kh.clone().jwk().unwrap();

            assert!(did.starts_with("did:key:"));

            println!("DID generated: {}", did.clone());

            // Resolving
            let resolved = didkey.resolve(&did, Default::default()).await;
            assert!(resolved.metadata.error.is_none());

            let doc = resolved.doc.unwrap();

            // DIDDoc assertions
            assert_eq!(doc.id, did);

            let formatted = serde_json::to_string_pretty(&doc).unwrap();
            println!("DID doc resolved:\n{}", formatted);

            let ver_method = doc
                .verification_method
                .unwrap()
                .to_vec()
                .first()
                .unwrap()
                .to_owned();
            assert!(matches!(ver_method, VerificationMethod::Map(_)));

            let VerificationMethod::Map(map) = ver_method else {
                unreachable!()
            };

            assert!(map.id.starts_with(&did));
            assert_eq!(map.controller, did);
            assert_eq!(map.public_key_jwk.unwrap(), jwk);
        }
    }
}
