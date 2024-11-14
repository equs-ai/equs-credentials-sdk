use super::didpeer::SpruceCompatibleDIDPeer;
use async_trait::async_trait;
use ssi::did::DIDMethods;
use ssi::did_resolve::DIDResolver as SpruceResolver;
use tracing::{instrument, trace, Level};

use crate::did::{DIDResolver, Resolution, ResolveOptions};

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
        impls.insert(Box::new(did_web::DIDWeb {}));
        impls.insert(Box::new(SpruceCompatibleDIDPeer::new()));

        Self { impls }
    }
}

#[async_trait]
impl DIDResolver for UniversalResolver {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    async fn resolve(&self, did: &str, options: ResolveOptions) -> Resolution {
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

#[cfg(test)]
mod tests {
    use crate::did::didkey::DIDKey;
    use crate::did::universal::UniversalResolver;
    use crate::did::{DIDResolver, DID};
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::{CreateOptions, Kms};
    use serde_json::json;

    #[tokio::test]
    async fn universal_resolver_supports_didkey() {
        let resolver = UniversalResolver::new();
        let did = didkey().await;

        let resolution = resolver.resolve(&did, Default::default()).await;
        assert!(resolution.metadata.error.is_none());
        assert_eq!(resolution.doc.unwrap().id, did);

        let vm = resolver.resolve_verification_method(&did).await.unwrap();
        assert!(vm.id.starts_with(&did));
    }

    #[tokio::test]
    async fn universal_resolver_supports_didweb() {
        let mut server = mockito::Server::new_async().await;
        let port_idx = server.url().rfind(':').unwrap() + 1;
        let port = &server.url()[port_idx..];

        let did = format!("did:web:localhost%3A{port}");

        let mock = server
            .mock("GET", "/.well-known/did.json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!(
                    {
                        "@context": [
                          "https://www.w3.org/ns/did/v1",
                          "https://w3id.org/security#Ed25519VerificationKey2020"
                        ],
                        "id": &did,
                        "verificationMethod": [
                          {
                            "id": did.to_string() + "#key-0",
                            "type": "Ed25519VerificationKey2020",
                            "controller": &did,
                            "publicKeyJwk": {
                              "kty": "OKP",
                              "crv": "Ed25519",
                              "x": "pbaXXx7XTNbX9ExtlLm2YECzixhs1_BLSD79SwtRTPY"
                            }
                          }
                        ]
                      }
                )
                .to_string(),
            )
            .create();

        let resolver = UniversalResolver::new();

        let resolution = resolver.resolve(&did, Default::default()).await;

        assert!(resolution.metadata.error.is_none());
        assert_eq!(resolution.doc.unwrap().id, did);

        let vm = resolver.resolve_verification_method(&did).await.unwrap();
        assert!(vm.id.starts_with(&did));
    }

    #[tokio::test]
    async fn universal_resolver_fails_on_unsupported_method() {
        let resolver = UniversalResolver::new();
        let did = "did:example:12345";

        let resolution = resolver.resolve(did, Default::default()).await;
        assert!(resolution.metadata.error.is_some());
    }

    async fn didkey() -> DID {
        let kms = LocalKms::new();
        let didkey = DIDKey::new();

        let (_, kh) = kms
            .create_and_handle(kms::KeyType::P256, CreateOptions {})
            .await
            .unwrap();

        didkey.generate(kh.clone()).unwrap()
    }
}
