//! Universal DID Resolver.

use crate::did::didpeer::DIDPeer;
use crate::did::didweb::DIDWeb;
use crate::did::{
    MethodAlreadyExistsSnafu, ProofValidationError, ResolutionError, ResolutionOutput,
};
use crate::http::HttpClient;
use crate::utils::wasm::{WasmNotSend, WasmNotSync};
use async_trait::async_trait;
use iref::Iri;
use ssi::JWK;
use ssi::dids::resolution::{Options, Output};
use ssi::dids::{AnyDidMethod, DID, DIDResolver as SpruceResolver, VerificationMethodDIDResolver};
use ssi::jwk::JWKResolver;
use ssi::prelude::AnyMethod;
use ssi::verification_methods::{
    ReferenceOrOwnedRef, ResolutionOptions, VerificationMethodResolutionError,
    VerificationMethodResolver,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use tracing::{Level, instrument};

type Level_ = Level;

const EXISTING_DID_METHODS: [&str; 7] = ["ethr", "ion", "jwk", "key", "pkh", "tz", "web"];

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DIDResolver: WasmNotSend + WasmNotSync {
    /// Resolves a DID representation.
    ///
    /// Fetches the DID document representation referenced by the input DID
    /// using the given options.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    ///
    /// # Arguments
    ///
    /// * `did` - DID string in `[u8]` format
    /// * `options` - Resolution options
    ///
    /// # Returns
    /// `ResolutionOutput` with `DIDDoc`.
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<ResolutionOutput, ResolutionError>;

    fn method_name(&self) -> String;
}

/// An Universal `DID` resolver.
///
/// # Supported methods
///
/// `did:key`
/// `did:peer`
/// `did:web`
#[derive(Clone)]
pub struct UniversalResolver {
    dids: HashMap<String, Arc<dyn DIDResolver>>,
}
impl UniversalResolver {
    /// Creates a new UniversalResolver. Created resolver supports `did:key`, `did:peer` and `did:web` methods.
    ///
    /// # Arguments
    ///
    /// * `http_client` - A Http client that implements [HttpClient] trait.
    pub fn new(http_client: Arc<impl HttpClient + 'static>) -> Self {
        let mut resolver = Self::default();
        resolver
            .dids
            .insert("web".to_string(), Arc::new(DIDWeb::new(http_client)));

        resolver
    }

    /// Adds a new DID resolver.
    ///
    /// Using this method, a new resolver can be added to extend support for additional DID methods.
    ///
    /// # Arguments
    ///
    /// * `resolver` - An instance of a type that implements [`DIDResolver`].
    ///
    /// # Errors
    ///
    /// `MethodAlreadyExists` if a resolver with the same method name already exists.
    pub fn add_resolver(&mut self, resolver: impl DIDResolver + 'static) -> super::Result<()> {
        if self.already_exists(resolver.method_name().as_str()) {
            MethodAlreadyExistsSnafu {
                method: resolver.method_name(),
            }
            .fail()?
        }
        self.dids.insert(resolver.method_name(), Arc::new(resolver));
        Ok(())
    }

    fn already_exists(&self, method: &str) -> bool {
        EXISTING_DID_METHODS.contains(&method) || self.dids.contains_key(method)
    }
}

impl Default for UniversalResolver {
    fn default() -> Self {
        let did_peer = DIDPeer::new();
        let mut dids: HashMap<String, Arc<dyn DIDResolver>> = HashMap::new();
        dids.insert(did_peer.method_name(), Arc::new(did_peer));
        Self { dids }
    }
}

impl SpruceResolver for UniversalResolver {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<Output<Vec<u8>>, ResolutionError> {
        let custom = self.dids.get(did.method_name());

        let result: Output<Vec<u8>> = if let Some(custom) = custom {
            let resolution = custom.resolve_representation(did, options).await?;

            Output::<Vec<u8>>::new(
                resolution.document.to_bytes(),
                resolution.document_metadata,
                resolution.metadata,
            )
        } else {
            AnyDidMethod::default()
                .resolve_representation(did, options)
                .await?
        };

        Ok(Output {
            metadata: result.metadata,
            document: result.document,
            document_metadata: result.document_metadata,
        })
    }
}

impl VerificationMethodResolver for UniversalResolver {
    type Method = AnyMethod;

    #[instrument(level = Level::TRACE, skip(self, options), ret())]
    async fn resolve_verification_method_with(
        &self,
        issuer: Option<&Iri>,
        method: Option<ReferenceOrOwnedRef<'_, Self::Method>>,
        options: ResolutionOptions,
    ) -> Result<Cow<'_, Self::Method>, VerificationMethodResolutionError> {
        let vmdr = VerificationMethodDIDResolver::new(self.clone());
        let vm = vmdr
            .resolve_verification_method_with(issuer, method, options)
            .await?
            .deref()
            .clone();

        Ok(Cow::Owned(vm))
    }
}

impl JWKResolver for UniversalResolver {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn fetch_public_jwk(
        &self,
        key_id: Option<&str>,
    ) -> Result<Cow<'_, JWK>, ProofValidationError> {
        let resolver: VerificationMethodDIDResolver<_, AnyMethod> =
            VerificationMethodDIDResolver::new(self.clone());

        let jwk = resolver.fetch_public_jwk(key_id).await?.deref().clone();

        Ok(Cow::Owned(jwk))
    }
}

#[cfg(test)]
mod tests {
    use crate::did::didkey::DIDKey;
    use crate::did::universal::{DIDResolver, UniversalResolver};
    use crate::did::{DID, DIDResolver as SpruceResolver, DocumentMetadata, ResolutionOutput};
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::{CreateOptions, Kms};
    use async_trait::async_trait;
    use rstest::rstest;
    use serde_json::json;
    use ssi::dids::resolution::{Error, Metadata, Options, Output};

    #[tokio::test]
    async fn universal_resolver_supports_didkey() {
        let resolver = UniversalResolver::default();
        let did_key = didkey().await;
        let did = ssi::dids::DID::new(&did_key).unwrap();

        let resolution = resolver.resolve(did).await.unwrap();
        assert!(resolution.metadata.content_type.is_some());
        assert_eq!(resolution.document.id.as_did(), did);

        let vm = resolver
            .resolve_into_any_verification_method(did)
            .await
            .unwrap()
            .unwrap();
        assert!(vm.id.starts_with(&did_key));
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

        let resolver = UniversalResolver::default();

        let resolution = resolver
            .resolve(ssi::dids::DID::new(&did).unwrap())
            .await
            .unwrap();

        assert!(resolution.metadata.content_type.is_some());
        assert_eq!(resolution.document.id.as_did().to_string(), did);

        let vm = resolver
            .resolve_into_any_verification_method(ssi::dids::DID::new(&did).unwrap())
            .await
            .unwrap()
            .unwrap();

        assert!(vm.id.to_string().starts_with(&did));
    }

    #[tokio::test]
    async fn universal_resolver_fails_on_unsupported_method() {
        let resolver = UniversalResolver::default();
        let did = "did:example:12345";

        let resolution = resolver
            .resolve(ssi::dids::DID::new(did).unwrap())
            .await
            .err();
        assert!(resolution.unwrap().to_string().contains("not supported"));
    }
    #[tokio::test]
    async fn universal_resolver_uses_custom_did_resolver() {
        let mut resolver = UniversalResolver::default();
        resolver
            .add_resolver(MockDIDResolver {
                method_name: "mock".to_string(),
            })
            .unwrap();
        let did = ssi::dids::DID::new("did:mock:12345").unwrap();

        let resolution = resolver
            .resolve_representation(did, Default::default())
            .await
            .unwrap();

        assert_eq!(
            String::from_utf8(resolution.document).unwrap(),
            mock_resolution_document(did)
        );
    }
    #[tokio::test]
    async fn universal_resolver_uses_several_custom_did_resolvers() {
        let mut resolver = UniversalResolver::default();
        resolver
            .add_resolver(MockDIDResolver {
                method_name: "mock".to_string(),
            })
            .unwrap();
        resolver
            .add_resolver(MockDIDResolver {
                method_name: "anothermock".to_string(),
            })
            .unwrap();
        let did_mock = ssi::dids::DID::new("did:mock:12345").unwrap();
        let did_another_mock = ssi::dids::DID::new("did:anothermock:12345").unwrap();

        let resolution_mock = resolver
            .resolve_representation(did_mock, Default::default())
            .await
            .unwrap();
        let resolution_another_mock = resolver
            .resolve_representation(did_another_mock, Default::default())
            .await
            .unwrap();

        assert_eq!(
            String::from_utf8(resolution_mock.document).unwrap(),
            mock_resolution_document(did_mock)
        );
        assert_eq!(
            String::from_utf8(resolution_another_mock.document).unwrap(),
            mock_resolution_document(did_another_mock)
        );
    }

    #[rstest]
    #[case("mock", "mock")]
    #[case("mock", "peer")]
    #[case("web", "peer")]
    #[case("web", "key")]
    #[tokio::test]
    #[should_panic(expected = "Method already exists")]
    async fn universal_resolver_throws_error_on_adding_already_existing_method(
        #[case] method1: String,
        #[case] method2: String,
    ) {
        let mut resolver = UniversalResolver::default();
        resolver
            .add_resolver(MockDIDResolver {
                method_name: method1,
            })
            .unwrap();
        resolver
            .add_resolver(MockDIDResolver {
                method_name: method2,
            })
            .unwrap();
    }

    async fn didkey() -> DID {
        let kms = LocalKms::new();

        let (_, kh) = kms
            .create_and_handle(kms::KeyType::P256, CreateOptions::default())
            .await
            .unwrap();

        DIDKey::generate(kh.clone()).unwrap()
    }

    struct MockDIDResolver {
        method_name: String,
    }

    #[async_trait]
    impl DIDResolver for MockDIDResolver {
        async fn resolve_representation<'a>(
            &'a self,
            did: &'a ssi::dids::DID,
            options: Options,
        ) -> Result<ResolutionOutput, Error> {
            Ok(Output {
                metadata: Metadata::default(),
                document: serde_json::from_str(&mock_resolution_document(did)).unwrap(),
                document_metadata: DocumentMetadata::default(),
            })
        }
        fn method_name(&self) -> String {
            self.method_name.to_string()
        }
    }

    fn mock_resolution_document(did: &ssi::dids::DID) -> String {
        json!(
            {
                "id": &did.to_string(),
                "verificationMethod": [
                  {
                    "id": did.to_string() + "#key-0",
                    "type": "Ed25519VerificationKey2020",
                    "controller": &did.to_string(),
                    "publicKeyJwk": {
                      "kty": "OKP",
                      "crv": "Ed25519",
                      "x": "pbaXXx7XTNbX9ExtlLm2YECzixhs1_BLSD79SwtRTPY"
                    }
                  }
                ],
                "@context": [
                  "https://www.mockdid.org/ns/did/v1",
                  "https://mockdid.org/security#Ed25519VerificationKey2020"
                ]
              }
        )
        .to_string()
    }
}
