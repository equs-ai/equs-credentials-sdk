use async_trait::async_trait;
use ssi::did::{DIDMethod, Source};
use ssi::did_resolve::DIDResolver as SpruceResolver;

use crate::core_::{crypto, did};
use crate::core_::did::{DID, DIDResolver, Resolution, ResolveOptions, VerificationMethodMap};
use crate::impls::did::resolve_verification_method;

pub struct DIDKey {
    method: did_method_key::DIDKey,
}

impl DIDKey {
    pub fn new() -> Self {
        Self { method: did_method_key::DIDKey {} }
    }

    pub fn generate<K>(&self, key: K) -> Result<DID, did::Error>
    where
        K: crypto::Key,
    {
        let Some(jwk) = key.jwk() else {
            return Err(did::Error::KeyNotSupported)
        };

        let did = self.method.generate(&Source::Key(&jwk));
        did.ok_or_else(|| did::Error::GenerationError)
    }
}

#[async_trait]
impl DIDResolver for DIDKey {
    async fn resolve(&self, did: &DID, options: ResolveOptions) -> Resolution {
        let (metadata, doc, doc_metadata) = self.method.to_resolver().resolve(did, &options.input).await;
        Resolution { doc, metadata, doc_metadata }
    }

    async fn resolve_verification_method(&self, did_url: &str) -> Result<VerificationMethodMap, did::Error> {
        resolve_verification_method(self.method.to_resolver(), did_url).await
    }

    fn as_spruce_resolver(&self) -> &dyn SpruceResolver {
        self.method.to_resolver()
    }
}

#[cfg(test)]
mod tests {
    use ssi::did::VerificationMethod;

    use crate::core_::crypto::Key;
    use crate::core_::did::DIDResolver;
    use crate::core_::kms;
    use crate::core_::kms::{CreateOptions, Kms};
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::kms::inmem::LocalKms;

    #[tokio::test]
    async fn e2e() {
        // Init
        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();

        for kt in vec![kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Key
            let (_, kh) = kms.create_and_handle(kt, CreateOptions {}).await.unwrap();

            // Creation
            let created = didkey.generate(kh.clone());
            assert!(created.is_ok());
            let jwk = kh.clone().jwk().unwrap();

            let did = created.unwrap();
            assert!(did.starts_with("did:key:"));

            println!("DID generated: {}", did.clone());

            // Resolving
            let resolved = didkey.resolve(&did, Default::default()).await;
            assert!(resolved.metadata.error.is_none());

            let doc = resolved.doc;
            assert!(doc.is_some());
            let doc = doc.unwrap();

            // DIDDoc assertions
            assert_eq!(doc.id, did);

            let formatted = serde_json::to_string_pretty(&doc).unwrap();
            println!("DID doc resolved:\n{}", formatted);

            let ver_method = doc.verification_method.unwrap().to_vec().get(0).unwrap().to_owned();
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