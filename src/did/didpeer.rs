use crate::crypto::{Key, JWK};
use crate::did::{
    DIDDoc, DIDResolver, DidDocGenerationSnafu, DidGenerationSnafu, Resolution, ResolveOptions,
    Result, DID,
};
use crate::kms::KeyType;
use async_trait::async_trait;
use did_parser_nom::DidUrl;
use did_peer::peer_did::numalgos::numalgo4::construction_did_doc::{
    DidPeer4ConstructionDidDocument, DidPeer4VerificationMethod,
};
use did_peer::peer_did::numalgos::numalgo4::Numalgo4;
use did_peer::peer_did::PeerDid;
use did_peer::resolver::options::PublicKeyEncoding;
use did_peer::resolver::{PeerDidResolutionOptions, PeerDidResolver};
use did_resolver::did_doc::schema::did_doc::DidDocument;
use did_resolver::did_doc::schema::types::jsonwebkey::JsonWebKey;
use did_resolver::did_doc::schema::verification_method::{
    PublicKeyField, VerificationMethodKind, VerificationMethodType,
};
use did_resolver::shared_types::did_document_metadata::DidDocumentMetadata;
use did_resolver::traits::resolvable::resolution_metadata::DidResolutionMetadata;
use did_resolver::traits::resolvable::resolution_output::DidResolutionOutput;
use did_resolver::traits::resolvable::DidResolvable;
use serde_json::Value;
use ssi::did_resolve::{DIDResolver as SpruceResolver, ResolutionMetadata};
use ssi_dids::did_resolve::{DocumentMetadata, ResolutionInputMetadata};
use ssi_dids::DIDMethod;
use std::collections::HashSet;
use tracing::{instrument, Level};

const DID_V1_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

const ED25519_VERIFICATION_KEY_2020: &str = "https://w3id.org/security#Ed25519VerificationKey2020";
const ED25519_VERIFICATION_KEY_2018: &str = "https://w3id.org/security#Ed25519VerificationKey2018";
const ECDSA_SECP_256K1_VERIFICATION_KEY_2019: &str =
    "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019";
const JSON_WEB_KEY_2020: &str = "https://w3id.org/security#JsonWebKey2020";
const BLS_12381_G1_KEY_2020: &str = "https://w3id.org/security#Bls12381G1Key2020";
const BLS_12381_G2_KEY_2020: &str = "https://w3id.org/security#Bls12381G2Key2020";
const ECDSA_SECP_256K1_RECOVERY_METHOD_2020: &str =
    "https://w3id.org/security#EcdsaSecp256k1RecoveryMethod2020";
const MULTIKEY: &str = "https://w3id.org/security#Multikey";

pub(crate) struct SpruceCompatibleDIDPeer(PeerDidResolver);

pub struct DIDPeer {
    resolver: SpruceCompatibleDIDPeer,
}

impl SpruceCompatibleDIDPeer {
    #[instrument(level = Level::TRACE)]
    pub fn new() -> Self {
        Self(PeerDidResolver::new())
    }
}

impl DIDPeer {
    #[instrument(level = Level::TRACE)]
    pub fn new() -> Self {
        DIDPeer {
            resolver: SpruceCompatibleDIDPeer::new(),
        }
    }

    #[instrument(level = Level::TRACE, skip(key), err(), ret())]
    pub fn generate_did_peer4(key: &impl Key, key_type: KeyType) -> Result<DID> {
        let jwk = key.jwk().ok_or_else(|| {
            DidDocGenerationSnafu {
                details: "the key does not support JWK form",
            }
            .build()
        })?;

        let mut construction_did_doc = DidPeer4ConstructionDidDocument::new();

        let did_url = DidUrl::parse("#key-0".into()).map_err(|err| {
            DidGenerationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let vm_type = match key_type {
            KeyType::Ed25519 => VerificationMethodType::Ed25519VerificationKey2020,
            KeyType::P256 => VerificationMethodType::EcdsaSecp256k1VerificationKey2019,
        };

        let pub_key_jwk = convert_jwk(&jwk).map_err(|err| {
            DidGenerationSnafu {
                details: "Public JWK generation failed",
            }
            .build()
        })?;

        let verification_method = DidPeer4VerificationMethod::builder()
            .id(did_url.clone())
            .verification_method_type(vm_type)
            .public_key(PublicKeyField::Jwk {
                public_key_jwk: pub_key_jwk,
            })
            .build();

        construction_did_doc.add_verification_method(verification_method);
        construction_did_doc.add_assertion_method_ref(did_url);

        let peer_did_4 = PeerDid::<Numalgo4>::new(construction_did_doc).map_err(|err| {
            DidGenerationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(peer_did_4.did().did().to_string())
    }
}

#[async_trait]
impl DIDResolver for DIDPeer {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn resolve(&self, did: &str, options: ResolveOptions) -> Resolution {
        let (metadata, doc, doc_metadata) = self
            .resolver
            .resolve(did, &ResolutionInputMetadata::default())
            .await;

        Resolution {
            metadata,
            doc,
            doc_metadata,
        }
    }

    #[instrument(level = Level::TRACE, skip(self))]
    fn as_spruce_resolver(&self) -> &dyn SpruceResolver {
        &self.resolver
    }
}

#[async_trait]
impl SpruceResolver for SpruceCompatibleDIDPeer {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Option<DIDDoc>, Option<DocumentMetadata>) {
        let did_peer = match did_parser_nom::Did::parse(did.to_string()) {
            Ok(did) => did,
            Err(err) => {
                return (
                    ResolutionMetadata {
                        error: Some(err.to_string()),
                        ..Default::default()
                    },
                    None,
                    None,
                )
            }
        };

        let resolution_result = self
            .0
            .resolve(
                &did_peer,
                &PeerDidResolutionOptions {
                    encoding: Some(PublicKeyEncoding::Base58),
                },
            )
            .await;

        let DidResolutionOutput {
            did_document,
            did_resolution_metadata,
            did_document_metadata,
        } = match resolution_result {
            Ok(result) => result,
            Err(err) => {
                return (
                    ResolutionMetadata {
                        error: Some(err.to_string()),
                        ..Default::default()
                    },
                    None,
                    None,
                )
            }
        };

        let did_doc = match convert_did_doc(&did_document) {
            Ok(doc) => doc,
            Err(err) => {
                return (
                    ResolutionMetadata {
                        error: Some(err.to_string()),
                        ..Default::default()
                    },
                    None,
                    None,
                )
            }
        };

        (
            convert_resolution_metadata(did_resolution_metadata),
            Some(did_doc),
            Some(convert_did_doc_metadata(did_document_metadata)),
        )
    }
}

impl DIDMethod for SpruceCompatibleDIDPeer {
    fn name(&self) -> &'static str {
        "peer"
    }

    fn to_resolver(&self) -> &dyn SpruceResolver {
        self
    }
}

#[instrument(level = Level::TRACE, ret())]
fn verification_method_context(vm: &VerificationMethodType) -> Option<&'static str> {
    match &vm {
        VerificationMethodType::Ed25519VerificationKey2018 => Some(ED25519_VERIFICATION_KEY_2018),
        VerificationMethodType::Ed25519VerificationKey2020 => Some(ED25519_VERIFICATION_KEY_2020),
        VerificationMethodType::EcdsaSecp256k1VerificationKey2019 => {
            Some(ECDSA_SECP_256K1_VERIFICATION_KEY_2019)
        }
        VerificationMethodType::JsonWebKey2020 => Some(JSON_WEB_KEY_2020),
        VerificationMethodType::Bls12381G1Key2020 => Some(BLS_12381_G1_KEY_2020),
        VerificationMethodType::Bls12381G2Key2020 => Some(BLS_12381_G2_KEY_2020),
        VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020 => {
            Some(ECDSA_SECP_256K1_RECOVERY_METHOD_2020)
        }
        VerificationMethodType::Multikey => Some(MULTIKEY),
        _ => None,
    }
}

#[instrument(level = Level::TRACE, err(), ret())]
fn convert_jwk(jwk: &JWK) -> serde_json::Result<JsonWebKey> {
    let jwk_str = serde_json::to_string(jwk)?;

    serde_json::from_str(&jwk_str)
}

#[instrument(level = Level::TRACE, err(), ret())]
fn convert_did_doc(did_doc: &DidDocument) -> Result<DIDDoc> {
    let Ok(Value::Object(mut did_doc_map)) = serde_json::to_value(did_doc) else {
        return DidDocGenerationSnafu {
            details: "Can not parse did documents as a json object",
        }
        .fail();
    };

    if did_doc_map.get("@context").is_none() {
        // find all VerificationMethod objects in the DID Document
        // and prepare contexts for each unique VerificationMethodType
        let vm_type_contexts: HashSet<String> = did_doc
            .assertion_method()
            .iter()
            .chain(did_doc.authentication().iter())
            .chain(did_doc.key_agreement().iter())
            .chain(did_doc.capability_invocation().iter())
            .chain(did_doc.capability_delegation().iter())
            .filter_map(|vm_kind| match vm_kind {
                VerificationMethodKind::Resolved(vm) => Some(vm),
                VerificationMethodKind::Resolvable(_) => None,
            })
            .chain(did_doc.verification_method().iter())
            .filter_map(|vm| verification_method_context(vm.verification_method_type()))
            .map(|s| s.to_string())
            .collect();

        let mut contexts = vec![Value::String(DID_V1_CONTEXT.to_string())];

        for vm_type_context in vm_type_contexts {
            contexts.push(Value::String(vm_type_context));
        }

        did_doc_map.insert("@context".to_string(), Value::Array(contexts));
    }

    // It was found that `ssi-0.7.0` crate implementation that is used
    // to generate w3c json-ld VC panics while preparing the issuer's proof
    // in a process of VC issuance in case of relative verification method id.
    //
    // Issuance Result: Err(VC error at: agent-sdk/src/vc/oid4vci/issuer.rs:216:25
    //  Cause: VC error
    //  Cause: Credential creation error: Missing verification relationship. Issuer: did:peer:4zQ...
    //           Proof purpose: AssertionMethod. Verification method id: #key-0)
    //
    //
    // To resolve that issue the following code converts relative verification
    // method ids (like `#key-0`) to absolute ones (like `did:peer:4...#key-0`).
    did_doc_map.get_mut("verificationMethod").and_then(|vms| {
        vms.as_array_mut().map(|vms_arr| {
            for vm in vms_arr {
                relative_verification_method_id_to_absolute(vm, did_doc.id().did());
            }
        })
    });

    serde_json::from_value(Value::Object(did_doc_map)).map_err(|err| {
        DidDocGenerationSnafu {
            details: err.to_string(),
        }
        .build()
    })
}

#[instrument(level = Level::TRACE)]
fn relative_verification_method_id_to_absolute(vm: &mut Value, did_str: &str) {
    let Some(vm_map) = vm.as_object_mut() else {
        return;
    };

    let Some(Value::String(id)) = vm_map.get("id") else {
        return;
    };

    if id.starts_with('#') {
        vm_map.insert("id".to_string(), Value::String(format!("{did_str}{id}")));
    }
}

#[instrument(level = Level::TRACE, ret())]
fn convert_did_doc_metadata(did_doc_metadata: DidDocumentMetadata) -> DocumentMetadata {
    DocumentMetadata {
        created: did_doc_metadata.created(),
        updated: did_doc_metadata.updated(),
        deactivated: did_doc_metadata.deactivated(),
        property_set: None,
    }
}

#[instrument(level = Level::TRACE, ret())]
fn convert_resolution_metadata(resolution_metadata: DidResolutionMetadata) -> ResolutionMetadata {
    ResolutionMetadata {
        error: resolution_metadata.error().map(|err| err.to_string()),
        content_type: resolution_metadata.content_type().cloned(),
        property_set: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms;
    use crate::kms::KeyType;
    use crate::kms::Kms;
    use rstest::rstest;

    #[rstest]
    #[case::ed25519(KeyType::Ed25519, "Ed25519VerificationKey2020")]
    #[case::p256(KeyType::P256, "EcdsaSecp256k1VerificationKey2019")]
    #[tokio::test]
    async fn did_peer_4_generating_succeeds_correctly(
        #[case] key_type: KeyType,
        #[case] vm_type: &str,
    ) {
        let kms = crate::inmem::kms::LocalKms::new();
        let (_, key) = kms
            .create_and_handle(key_type.clone(), kms::CreateOptions {})
            .await
            .unwrap();

        let did = DIDPeer::generate_did_peer4(&key, key_type).unwrap();

        assert!(did.starts_with("did:peer:4"));
        let did_peer = did_parser_nom::Did::parse(did).unwrap();

        // ensure that the DID is valid and can be resolved
        let DidResolutionOutput { did_document, .. } = PeerDidResolver::new()
            .resolve(
                &did_peer,
                &PeerDidResolutionOptions {
                    encoding: Some(PublicKeyEncoding::Base58),
                },
            )
            .await
            .unwrap();

        // ensure that the DID's verification method type is correct according to key type
        assert_eq!(
            did_document.verification_method()[0]
                .verification_method_type()
                .to_string(),
            vm_type.to_string()
        );

        assert!(!did_document.assertion_method().is_empty());
    }

    #[rstest]
    #[case::ed25519(
        sample_did_peer_4_ed25519(),
        "https://w3id.org/security#Ed25519VerificationKey2020"
    )]
    #[case::p256(
        sample_did_peer_4_p256(),
        "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019"
    )]
    #[tokio::test]
    async fn did_resolving_succeeds_correctly(#[case] did: &str, #[case] vm_context: &str) {
        let resolver = DIDPeer::new();

        let Resolution {
            metadata,
            doc,
            doc_metadata,
        } = resolver.resolve(did, ResolveOptions::default()).await;

        assert_eq!(
            serde_json::to_value(doc.clone().unwrap().context.clone()).unwrap(),
            Value::Array(vec![
                Value::String("https://www.w3.org/ns/did/v1".to_string()),
                Value::String(vm_context.to_string())
            ])
        );

        assert_eq!(
            doc.clone().unwrap().verification_method.unwrap()[0].get_id(did),
            format!("{did}#key-0")
        );
    }

    #[rstest]
    #[case::empty_string("")]
    #[case::did_key("did:key:zDnaeWuPANDrwEAqBPqTGUTLVEeJRyDXwjLQAbtBFDY3ZUmWk")]
    #[case::did_peer4_short("did:peer:4zQmaT2A39nfFt7AhQ3TUqtXsyViE9TPzgyeEwoD9x2Tz3TZ")]
    #[tokio::test]
    async fn did_resolving_fails_when_did_is_not_did_peer4_long(#[case] did: &str) {
        let resolver = DIDPeer::new();

        let resolution_result = resolver.resolve(did, ResolveOptions::default()).await;

        assert!(matches!(
            resolution_result,
            Resolution {
                metadata: ResolutionMetadata {
                    error: Some(_),
                    content_type: None,
                    property_set: None
                },
                doc: None,
                doc_metadata: None
            }
        ));
    }

    fn sample_did_peer_4_ed25519() -> &'static str {
        "did:peer:4zQmdb4o7AKtvjc1oKLrFB3uY8U7QWLkixELKoYjp7aJNxQx:\
        zHdLySSvWoezKPJrPgxUa9B2YryAUB1hfkyphQHWb9UU5y6U7V8AYLxxspM\
        gCHpMxXZgxZd1sBjgXdMS8GBr8QxRcFsxzR22Zr2uD1bypN34enDUs4xeVF\
        5Na2JYzd31qjs4fDeLGjzD9JVAJCqbCV7sczwNkMwYaTLBWnat86JmHFbZ2\
        jKgf2uQoHrTtWfhd647gSpKVPaeikRgqjwS8FNaLhAGZGHzPneMvfcHn8Mx\
        SEufBy33KXYruYBE7T3MjtXfbBPwbQsmbV8MmQJix"
    }

    fn sample_did_peer_4_p256() -> &'static str {
        "did:peer:4zQmYJExhNkzEusuo2wtPUjELHd5DjWjqou8zK1DjkUbYJQN:\
        z6vBHxfLVdamf8vJxTVo9wcvuV1dLpYaaiseoXFtRjCkXwL77GQeG7g73Eq\
        vDYXkRZdVeNV3sAHCMXERXEFFxJUQYz4xrVEeoh7oBJL4xSCzejNt7s4iZQ\
        czEJ82FJJvqUoj825UF49u1BReWbYskwLWHqmhMYE8C27pbSLifBtRdYxv5\
        QoKHzohD6Bn99Nj7SfKkfpV7v6CoSEabVVn26hvLFc5Fd2iGwjBR4hMS4rf\
        e3bZQQSQuFQzLQDQ6RLSM6AW3JLaZ6EZ1HZd5d1GVurqkFyBjn5RFZpvJat\
        xPjekSTxVBGuywNMWZo3giqBZU7rH9XiTDRqvQj7PEog1qWHD4nt5gnY"
    }
}
