//! did:peer method.

use crate::crypto::{Key, JWK};
use crate::did;
use crate::did::universal::DIDResolver;
use crate::did::{
    DidDocGenerationSnafu, DidGenerationSnafu, ResolutionOutput, Result, VerificationMethodKey,
    VerificationRelationshipType,
};
use async_trait::async_trait;
use did_peer::peer_did::numalgos::numalgo4::construction_did_doc::{
    DidPeer4ConstructionDidDocument, DidPeer4VerificationMethod,
};
use did_peer::peer_did::numalgos::numalgo4::Numalgo4;
use did_peer::peer_did::PeerDid;
use did_peer::resolver::options::PublicKeyEncoding;
use did_peer::resolver::{PeerDidResolutionOptions, PeerDidResolver};
use did_resolver::did_doc::schema::did_doc::DidDocument;
use did_resolver::did_doc::schema::service::Service;
use did_resolver::did_doc::schema::types::jsonwebkey::JsonWebKey;
use did_resolver::did_doc::schema::verification_method::{
    PublicKeyField, VerificationMethodKind, VerificationMethodType,
};
use did_resolver::shared_types::did_document_metadata::DidDocumentMetadata;
use did_resolver::traits::resolvable::resolution_metadata::DidResolutionMetadata;
use did_resolver::traits::resolvable::resolution_output::DidResolutionOutput;
use did_resolver::traits::resolvable::DidResolvable;
use serde_json::Value;
use snafu::ensure;
use ssi::dids::resolution::{Error, Options, Output};
use ssi::dids::DIDMethod;
use std::collections::HashSet;
use tracing::{instrument, Level};

type DidUrl = did_parser_nom::DidUrl;
pub type DidPeerService = Service;
type VerificationMethod = did_resolver::did_doc::schema::verification_method::VerificationMethod;

type Level_ = Level;

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

/// A general `did:peer` service.
pub struct DIDPeer {
    resolver: PeerDidResolver,
}

impl DIDPeer {
    #[instrument(level = Level::TRACE)]
    pub fn new() -> Self {
        DIDPeer {
            resolver: PeerDidResolver::new(),
        }
    }

    /// Generates a `did:peer` using Peer DID Method 4.
    ///
    /// # Parameters
    ///
    /// - `keys`: [VerificationMethodKey] objects representing the cryptographic keys
    ///   that will be embedded in the DID document.
    /// - `services`: [did::Service] objects representing the service
    ///   endpoints that will be embedded in the DID document.
    ///
    /// # Returns
    ///
    /// A new generated `did:peer`.
    ///
    /// # Errors
    ///
    /// * [did::Error::DidGeneration] - `DID` generation failure.
    #[instrument(level = Level::TRACE, skip(keys), err(), ret())]
    pub fn generate_did_peer4(
        keys: &[VerificationMethodKey],
        services: &[Service],
    ) -> Result<did::DID> {
        ensure!(
            !keys.is_empty(),
            DidGenerationSnafu {
                details: "To generate did:peer, at least one key must be provided."
            }
        );

        let mut construction_did_doc = DidPeer4ConstructionDidDocument::default();

        for (index, key) in keys.iter().enumerate() {
            Self::add_verification_method(
                index,
                key.key,
                &key.verification_relationships,
                &mut construction_did_doc,
            )?
        }

        for service in services {
            construction_did_doc.add_service(service.clone())
        }

        let peer_did_4 = PeerDid::<Numalgo4>::new(construction_did_doc).map_err(|err| {
            DidGenerationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(peer_did_4.did().did().to_string())
    }

    fn add_verification_method(
        index: usize,
        key: &dyn Key,
        verification_relationships: &HashSet<VerificationRelationshipType>,
        construction_did_doc: &mut DidPeer4ConstructionDidDocument,
    ) -> Result<()> {
        let jwk = key.jwk().ok_or_else(|| {
            DidDocGenerationSnafu {
                details: "the key does not support JWK form",
            }
            .build()
        })?;

        let vm_id = DidUrl::parse(format!("#key-{index}")).map_err(|err| {
            DidGenerationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let pub_key_jwk = convert_jwk(&jwk).map_err(|err| {
            DidGenerationSnafu {
                details: format!("Public JWK generation failed {err}"),
            }
            .build()
        })?;

        let verification_method = DidPeer4VerificationMethod::builder()
            .id(vm_id.clone())
            .verification_method_type(VerificationMethodType::JsonWebKey2020)
            .public_key(PublicKeyField::Jwk {
                public_key_jwk: pub_key_jwk,
            })
            .build();

        construction_did_doc.add_verification_method(verification_method);

        for verification_relationship in verification_relationships {
            match verification_relationship {
                VerificationRelationshipType::Authentication => {
                    construction_did_doc.add_authentication_ref(vm_id.clone())
                }
                VerificationRelationshipType::Assertion => {
                    construction_did_doc.add_assertion_method_ref(vm_id.clone())
                }
                VerificationRelationshipType::KeyAgreement => {
                    // TODO: Create Verification Method with the type X25519KeyAgreementKey2020 for ED25519
                    construction_did_doc.add_key_agreement_ref(vm_id.clone());
                }
                VerificationRelationshipType::CapabilityInvocation => {
                    construction_did_doc.add_capability_invocation_ref(vm_id.clone());
                }
                VerificationRelationshipType::CapabilityDelegation => {
                    construction_did_doc.add_capability_delegation_ref(vm_id.clone());
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl DIDResolver for DIDPeer {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a ssi::dids::DID,
        options: Options,
    ) -> std::result::Result<ResolutionOutput, Error> {
        let did_peer = did_parser_nom::Did::parse(did.to_string()).map_err(|err| {
            Error::Internal(format!("could not parse did:peer = {}: {}", did, err))
        })?;

        let DidResolutionOutput {
            did_document,
            did_resolution_metadata,
            did_document_metadata,
        } = self
            .resolver
            .resolve(
                &did_peer,
                &PeerDidResolutionOptions {
                    encoding: Some(PublicKeyEncoding::Base58),
                },
            )
            .await
            .map_err(|e| Error::NoRepresentation)?;

        let did_doc = convert_did_doc(&did_document)?;

        Ok(Output {
            metadata: convert_resolution_metadata(did_resolution_metadata),
            document: did_doc,
            document_metadata: convert_did_doc_metadata(did_document_metadata),
        })
    }

    fn method_name(&self) -> String {
        Self::DID_METHOD_NAME.to_string()
    }
}
impl DIDMethod for DIDPeer {
    const DID_METHOD_NAME: &'static str = "peer";
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
fn convert_did_doc(did_doc: &DidDocument) -> std::result::Result<did::DIDDoc, Error> {
    let mut did_doc_map = serde_json::to_value(did_doc)
        .map_err(|err| Error::InvalidData(ssi::dids::document::InvalidData::Json(err)))?
        .as_object()
        .cloned()
        .ok_or_else(|| {
            Error::RepresentationNotSupported(
                "could not convert did doc to JSON object".to_string(),
            )
        })?;

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

        let mut contexts = vec![serde_json::Value::String(DID_V1_CONTEXT.to_string())];

        for vm_type_context in vm_type_contexts {
            contexts.push(serde_json::Value::String(vm_type_context));
        }

        did_doc_map.insert("@context".to_string(), serde_json::Value::Array(contexts));
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
                relative_id_to_absolute(vm, did_doc.id().did());
            }
        })
    });

    did_doc_map.get_mut("service").and_then(|services| {
        services.as_array_mut().map(|services_arr| {
            for svc in services_arr {
                relative_id_to_absolute(svc, did_doc.id().did());

                let Some(svc_type) = svc.get("type") else {
                    return;
                };
                if svc_type != "DIDCommMessaging" {
                    return;
                }

                let Some(endpoint) = svc.get_mut("serviceEndpoint") else {
                    return;
                };

                match endpoint {
                    Value::Object(map) => {
                        relative_routing_keys_to_absolute(endpoint, did_doc.id().did());
                    }
                    Value::Array(endpoints) => {
                        endpoints.iter_mut().for_each(|endpoint| {
                            relative_routing_keys_to_absolute(endpoint, did_doc.id().did());
                        });
                    }
                    _ => return,
                }
            }
        })
    });

    serde_json::from_value(Value::Object(did_doc_map))
        .map_err(|e| Error::InvalidData(ssi::dids::document::InvalidData::JsonLd(e)))
}

#[instrument(level = Level::TRACE)]
fn relative_id_to_absolute(obj: &mut Value, did_str: &str) {
    let Some(map) = obj.as_object_mut() else {
        return;
    };

    let Some(Value::String(id)) = map.get("id") else {
        return;
    };

    if id.starts_with('#') {
        map.insert("id".to_string(), Value::String(format!("{did_str}{id}")));
    }
}

#[instrument(level = Level::TRACE)]
fn relative_routing_keys_to_absolute(obj: &mut Value, did_str: &str) {
    let Some(map) = obj.as_object_mut() else {
        return;
    };

    let Some(Value::Array(routing_keys)) = map.get_mut("routingKeys") else {
        return;
    };

    for key in routing_keys.iter_mut() {
        if let Value::String(key_str) = key {
            if key_str.starts_with('#') {
                *key_str = format!("{did_str}{key_str}");
            }
        }
    }
}

#[instrument(level = Level::TRACE, ret())]
fn convert_did_doc_metadata(did_doc_metadata: DidDocumentMetadata) -> did::DocumentMetadata {
    did::DocumentMetadata {
        deactivated: did_doc_metadata.deactivated(),
    }
}

#[instrument(level = Level::TRACE, ret())]
fn convert_resolution_metadata(
    resolution_metadata: DidResolutionMetadata,
) -> did::ResolutionMetadata {
    did::ResolutionMetadata {
        content_type: resolution_metadata.content_type().cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms;
    use crate::kms::KeyType;
    use crate::kms::Kms;
    use crate::utils::test_utils::no_jwk_key;
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
        let (_, key_0) = kms
            .create_and_handle(key_type.clone(), kms::CreateOptions::default())
            .await
            .unwrap();

        let (_, key_1) = kms
            .create_and_handle(key_type.clone(), kms::CreateOptions::default())
            .await
            .unwrap();

        let keys = vec![
            VerificationMethodKey {
                key: &key_0,
                verification_relationships: vec![
                    VerificationRelationshipType::Assertion,
                    VerificationRelationshipType::Authentication,
                ]
                .into_iter()
                .collect(),
            },
            VerificationMethodKey {
                key: &key_1,
                verification_relationships: vec![VerificationRelationshipType::KeyAgreement]
                    .into_iter()
                    .collect(),
            },
        ];

        let service_json: serde_json::Value = serde_json::json!({
            "id":"did:example:123#linked-domain",
            "type": "LinkedDomains",
            "serviceEndpoint": "https://bar.example.com/"
        });

        let service = serde_json::from_value(service_json.clone()).unwrap();

        let did = DIDPeer::generate_did_peer4(&keys, &[service]).unwrap();

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

        // ensure that the DID's verification methods are correct
        assert_eq!(
            serde_json::to_value(key_0.jwk().unwrap()).unwrap(),
            public_key_to_jwk(did_document.verification_method()[0].public_key_field()),
        );

        assert_eq!(
            serde_json::to_value(key_1.jwk().unwrap()).unwrap(),
            public_key_to_jwk(did_document.verification_method()[1].public_key_field()),
        );

        assert!(matches!(
            &did_document.authentication()[0],
            VerificationMethodKind::Resolvable(did_url) if did_url.did_url() == "#key-0",
        ));

        assert!(matches!(
            &did_document.assertion_method()[0],
            VerificationMethodKind::Resolvable(did_url) if did_url.did_url() == "#key-0"
        ));

        assert!(matches!(
            &did_document.key_agreement()[0],
            VerificationMethodKind::Resolvable(did_url) if did_url.did_url() == "#key-1"
        ));

        // ensure that Service is correct
        assert_eq!(
            serde_json::to_value(&did_document.service()[0]).unwrap(),
            service_json
        );
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

        let document = resolver
            .resolve_representation(ssi::dids::DID::new(&did).unwrap(), Default::default())
            .await
            .unwrap()
            .document;

        assert_eq!(
            serde_json::to_value(document.clone().property_set.get("@context").unwrap()).unwrap(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("https://www.w3.org/ns/did/v1".to_string()),
                serde_json::Value::String(vm_context.to_string())
            ])
        );

        assert_eq!(
            document.clone().verification_method[0].id.to_string(),
            format!("{did}#key-0")
        );
    }

    #[tokio::test]
    async fn did_peer_4_generating_fails_on_invalid_jwk() {
        let result = DIDPeer::generate_did_peer4(
            &[VerificationMethodKey {
                key: &no_jwk_key(),
                verification_relationships: Default::default(),
            }],
            &[],
        );

        assert!(matches!(
            result.err().unwrap(),
            did::Error::DidDocGeneration { .. }
        ));
    }

    #[rstest]
    #[case::did_key("did:key:zDnaeWuPANDrwEAqBPqTGUTLVEeJRyDXwjLQAbtBFDY3ZUmWk")]
    #[case::did_peer4_short("did:peer:4zQmaT2A39nfFt7AhQ3TUqtXsyViE9TPzgyeEwoD9x2Tz3TZ")]
    #[tokio::test]
    async fn did_resolving_fails_when_did_is_not_did_peer4_long(#[case] did: &str) {
        let resolver = DIDPeer::new();

        let resolution_result = resolver
            .resolve_representation(ssi::dids::DID::new(&did).unwrap(), Default::default())
            .await;

        assert!(resolution_result.is_err());
    }

    fn public_key_to_jwk(public_key: &PublicKeyField) -> serde_json::Value {
        match public_key {
            PublicKeyField::Jwk { public_key_jwk } => serde_json::to_value(public_key_jwk).unwrap(),
            _ => panic!("Unexpected public key type"),
        }
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
