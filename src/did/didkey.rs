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
    async fn resolve(&self, did: &str, options: ResolveOptions) -> Resolution {
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
    use crate::did::didkey::DIDKey;
    use crate::did::DIDResolver;
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::{CreateOptions, Kms};
    use crate::utils::test_utils::no_jwk_key;
    use ssi::did::VerificationMethod;

    const SAMPLE_DID: &str = "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6";
    const SAMPLE_DID_URL: &str = "did:key:zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6#zDnaefX6jBNVFnFeUPMRGo6exaVdJ1TRCwuhm296PbB5gPTj6";

    #[tokio::test]
    async fn didkey_generated_correctly() {
        let kms = LocalKms::new();
        let didkey = DIDKey::new();

        for kt in kms::SUPPORTED_KEYS {
            let (_, kh) = kms.create_and_handle(kt, CreateOptions {}).await.unwrap();

            let did = didkey.generate(kh.clone()).unwrap();
            assert!(did.starts_with("did:key:"));
        }
    }

    #[tokio::test]
    async fn didkey_resolved_correctly() {
        let didkey = DIDKey::new();

        let resolved = didkey.resolve(SAMPLE_DID, Default::default()).await;
        assert!(resolved.metadata.error.is_none());

        let doc = resolved.doc.unwrap();

        assert_eq!(doc.id, SAMPLE_DID.to_string());

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

        assert_eq!(map.id, SAMPLE_DID_URL);
        assert_eq!(map.controller, SAMPLE_DID);
    }

    #[tokio::test]
    async fn didkey_resolves_ver_method_correctly() {
        let didkey = DIDKey::new();

        let resolved = didkey
            .resolve_verification_method(SAMPLE_DID)
            .await
            .unwrap();
        assert_eq!(resolved.id, SAMPLE_DID_URL);
    }

    #[tokio::test]
    async fn didkey_generate_fails_on_invalid_jwk() {
        let didkey = DIDKey::new();

        assert!(didkey.generate(no_jwk_key()).is_err());
    }

    #[tokio::test]
    async fn didkey_resolve_fails_on_invalid_did() {
        let didkey = DIDKey::new();

        let resolved = didkey.resolve("not-a-did", Default::default()).await;
        assert!(resolved.metadata.error.is_some());
    }

    #[tokio::test]
    async fn didkey_resolve_ver_method_fails_on_invalid_did() {
        let didkey = DIDKey::new();

        let res = didkey.resolve_verification_method("not-a-did").await;
        assert!(res.is_err());
    }
}
