use super::didpeer::DIDPeer;
use crate::did::ProofValidationError;
use iref::Iri;
use ssi::dids::resolution::{Options, Output};
use ssi::dids::{AnyDidMethod, DIDMethod, DIDResolver, VerificationMethodDIDResolver, DID};
use ssi::jwk::JWKResolver;
use ssi::prelude::AnyMethod;
use ssi::verification_methods::{
    ReferenceOrOwnedRef, ResolutionOptions, VerificationMethodResolutionError,
    VerificationMethodResolver,
};
use ssi::JWK;
use std::borrow::Cow;
use std::ops::Deref;
use tracing::{instrument, Level};

type Level_ = Level;

/// An Universal `DID` resolver.
///
/// # Supported methods
///
/// `did:key`
/// `did:peer`
/// `did:web`
#[derive(Default, Clone)]
pub struct UniversalResolver {}

impl DIDResolver for UniversalResolver {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<Output<Vec<u8>>, ssi::dids::resolution::Error> {
        let result = match did.method_name() {
            DIDPeer::DID_METHOD_NAME => DIDPeer::new().resolve_representation(did, options).await,
            _ => {
                AnyDidMethod::default()
                    .resolve_representation(did, options)
                    .await
            }
        }?;

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
    ) -> Result<Cow<Self::Method>, VerificationMethodResolutionError> {
        let vmdr = VerificationMethodDIDResolver::new(UniversalResolver {});
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
    ) -> Result<Cow<JWK>, ProofValidationError> {
        let resolver: VerificationMethodDIDResolver<_, AnyMethod> =
            VerificationMethodDIDResolver::new(UniversalResolver {});

        let jwk = resolver.fetch_public_jwk(key_id).await?.deref().clone();

        Ok(Cow::Owned(jwk))
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

    async fn didkey() -> DID {
        let kms = LocalKms::new();

        let (_, kh) = kms
            .create_and_handle(kms::KeyType::P256, CreateOptions::default())
            .await
            .unwrap();

        DIDKey::generate(kh.clone()).unwrap()
    }
}
