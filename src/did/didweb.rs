use crate::crypto::Key;
use crate::did::{
    DIDDoc, DIDResolver, DidDocGenerationSnafu, DidGenerationSnafu, InvalidDidFormatSnafu,
    KeyNotSupportedSnafu, Resolution, ResolveOptions, Result, DID,
};
use async_trait::async_trait;
use iref::IriRefBuf;
use regex::Regex;
use ssi::did::{VerificationMethod, VerificationMethodMap};
use ssi::did_resolve::DIDResolver as SpruceResolver;
use ssi::jwk::Params;
use ssi_dids::DIDURL;
use ssi_dids::{Context, Contexts};
use std::str::FromStr;
use tracing::{instrument, Level};
use url::Url;

const ED25519_VM_TYPE: &str = "Ed25519VerificationKey2020";
const ED25519_VM_TYPE_IRI: &str = "https://w3id.org/security#Ed25519VerificationKey2020";
const ECDSASECP256K1_VM_TYPE: &str = "EcdsaSecp256k1VerificationKey2019";
const ECDSASECP256K1_VM_TYPE_IRI: &str =
    "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019";

// ([a-z0-9][a-z0-9\-]*)      first part of domain name
// (\.[a-z0-9][a-z0-9\-]*)*   any number of domain name parts
// (%3A[0-9]+)?               optional port segment
// (:[A-Za-z0-9_\-\.]+)*      any number of path segments
const DID_WEB_PATTERN: &str =
    r"^did:web:([a-z0-9][a-z0-9\-]*)(\.[a-z0-9][a-z0-9\-]*)*(%3A[0-9]+)?(:[A-Za-z0-9_\-\.]+)*$";

/// Resolver for the `did:web` method.
///
/// Implements common [DIDResolver] for resolving DIDs.
pub struct DIDWeb {
    did_web_resolver: did_web::DIDWeb,
}

impl DIDWeb {
    #[instrument(level = Level::TRACE)]
    pub fn new() -> Self {
        Self {
            did_web_resolver: did_web::DIDWeb {},
        }
    }

    /// Generate a `did:web` from a URL.
    ///
    /// # Arguments
    ///
    /// * `url` - a URL for which the [DID] is generated.
    ///
    /// # Returns
    ///
    /// A new [DID].
    ///
    /// # Errors
    ///
    /// * [crate::did::Error::DidGeneration] - can't generate [DID].
    #[instrument(level = Level::TRACE, err(), ret())]
    pub fn generate_did_from_url(url: &str) -> Result<DID> {
        let url = Url::parse(url).map_err(|_| {
            DidGenerationSnafu {
                details: format!("invalid url: {url}"),
            }
            .build()
        })?;

        let domain = url.domain().ok_or_else(|| {
            DidGenerationSnafu {
                details: "invalid url: domain name is not specified",
            }
            .build()
        })?;

        let allowed_scheme = if domain == "localhost" {
            "http"
        } else {
            "https"
        };

        if url.scheme() != allowed_scheme {
            return DidGenerationSnafu {
                details: format!("invalid url scheme: {}", url.scheme()),
            }
            .fail();
        }

        let port = url.port().map_or(String::new(), |p| format!("%3A{p}"));
        let path_segments = url
            .path_segments()
            .unwrap()
            .filter(|segment| !segment.is_empty())
            .map(|segment| format!(":{segment}"))
            .fold(String::new(), |acc, item| format!("{acc}{item}"));

        let did = format!("did:web:{domain}{port}{path_segments}");

        Ok(did)
    }

    /// Generate a [DIDDoc] for a `DID`.
    ///
    /// # Arguments
    ///
    /// * `did` - a `DID` for which the [DIDDoc] is generated.
    /// * `key` - a public key [Key] that is a verification method for the `DID`.
    ///
    /// # Returns
    ///
    /// A new [DIDDoc].
    ///
    /// # Errors
    ///
    /// * [crate::did::Error::KeyNotSupported] - key type is not supported.
    #[instrument(level = Level::TRACE, skip(key), err(), ret())]
    pub fn generate_did_document(did: &str, key: &impl Key) -> Result<DIDDoc> {
        validate_didweb(did)?;

        let jwk = key.jwk().ok_or_else(|| {
            DidDocGenerationSnafu {
                details: "the key does not support JWK form",
            }
            .build()
        })?;

        let (vm_type, vm_type_iri) = match jwk.params {
            Params::OKP(ref params) => match &params.curve[..] {
                "Ed25519" => (ED25519_VM_TYPE, ED25519_VM_TYPE_IRI),
                _ => {
                    return KeyNotSupportedSnafu {
                        type_: params.curve.clone(),
                    }
                    .fail();
                }
            },
            Params::EC(ref params) => match params.curve {
                Some(ref curve) => match &curve[..] {
                    "P-256" => (ECDSASECP256K1_VM_TYPE, ECDSASECP256K1_VM_TYPE_IRI),
                    _ => {
                        return KeyNotSupportedSnafu {
                            type_: curve.clone(),
                        }
                        .fail();
                    }
                },
                None => {
                    return KeyNotSupportedSnafu {
                        type_: "unknown Elliptic Curve Public Key",
                    }
                    .fail();
                }
            },
            _ => {
                return KeyNotSupportedSnafu {
                    type_: format!("{:?}", jwk.params),
                }
                .fail();
            }
        };

        let mut did_doc = DIDDoc::new(did);

        did_doc.context = Contexts::Many(vec![
            Context::URI(IriRefBuf::from_str("https://www.w3.org/ns/did/v1").unwrap()),
            Context::URI(IriRefBuf::from_str(vm_type_iri).unwrap()),
        ]);

        let default_vm = VerificationMethodMap {
            id: format!("{}#key-0", did),
            type_: vm_type.to_string(),
            controller: did.to_string(),
            public_key_jwk: Some(jwk),
            ..Default::default()
        };

        did_doc.verification_method = Some(vec![VerificationMethod::Map(default_vm.to_owned())]);

        let did_url: DIDURL = default_vm.id.try_into().map_err(|_| {
            DidDocGenerationSnafu {
                details: "DIDURL parsing failed",
            }
            .build()
        })?;

        did_doc.assertion_method = Some(vec![VerificationMethod::DIDURL(did_url)]);

        Ok(did_doc)
    }
}

fn validate_didweb(did: &str) -> Result<()> {
    let re = Regex::new(DID_WEB_PATTERN).unwrap();

    if !re.is_match(did) {
        return InvalidDidFormatSnafu { details: did }.fail();
    }

    Ok(())
}

#[async_trait]
impl DIDResolver for DIDWeb {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn resolve(&self, did: &str, options: ResolveOptions) -> Resolution {
        let (metadata, doc, doc_metadata) =
            self.did_web_resolver.resolve(did, &options.input).await;

        Resolution {
            doc,
            metadata,
            doc_metadata,
        }
    }

    #[instrument(level = Level::TRACE, skip_all)]
    fn as_spruce_resolver(&self) -> &dyn SpruceResolver {
        &self.did_web_resolver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::Error;
    use crate::kms;
    use crate::kms::KeyType;
    use crate::kms::Kms;
    use rstest::rstest;
    use serde_json::json;

    #[tokio::test]
    async fn did_without_port_and_path_is_generated_correctly() {
        let did = DIDWeb::generate_did_from_url("https://test.example.com").unwrap();
        assert_eq!(did, "did:web:test.example.com");
    }

    #[tokio::test]
    async fn did_with_port_is_generated_correctly() {
        let did = DIDWeb::generate_did_from_url("https://test.example.com:3000").unwrap();
        assert_eq!(did, "did:web:test.example.com%3A3000");
    }

    #[tokio::test]
    async fn did_with_path_is_generated_correctly() {
        let did =
            DIDWeb::generate_did_from_url("https://test.example.com/users/alice/project1").unwrap();
        assert_eq!(did, "did:web:test.example.com:users:alice:project1");
    }

    #[tokio::test]
    async fn did_generating_fails_when_url_scheme_is_http() {
        let result = DIDWeb::generate_did_from_url("http://test.example.com");

        assert!(matches!(
            result.err().unwrap(),
            Error::DidGeneration { details, location } if details == "invalid url scheme: http"
        ));
    }

    #[tokio::test]
    async fn did_generating_fails_when_url_contains_ip_address() {
        let result = DIDWeb::generate_did_from_url("https://127.0.0.1");

        assert!(matches!(
            result.err().unwrap(),
            Error::DidGeneration { details, location } if details == "invalid url: domain name is not specified"
        ));
    }

    #[rstest]
    #[case::p256((KeyType::P256, ECDSASECP256K1_VM_TYPE,ECDSASECP256K1_VM_TYPE_IRI))]
    #[case::ed25519((KeyType::Ed25519, ED25519_VM_TYPE, ED25519_VM_TYPE_IRI))]
    #[tokio::test]
    async fn did_doc_is_generated_correctly(#[case] test_case: (KeyType, &str, &str)) {
        let (key_type, vm_type, vm_type_iri) = test_case;

        let did = "did:web:test.example.com";
        let kms = crate::inmem::kms::LocalKms::new();
        let (_, key) = kms
            .create_and_handle(key_type, kms::CreateOptions {})
            .await
            .unwrap();

        let did_doc = DIDWeb::generate_did_document(did, &key).unwrap();

        assert_eq!(
            did_doc.context,
            serde_json::from_value(json!(["https://www.w3.org/ns/did/v1", vm_type_iri])).unwrap()
        );

        assert_eq!(did_doc.id, did);

        assert_eq!(
            did_doc.verification_method.as_ref().unwrap()[0],
            VerificationMethod::Map(VerificationMethodMap {
                id: format!("{did}#key-0"),
                type_: vm_type.to_string(),
                controller: did.to_string(),
                public_key_jwk: Some(key.jwk().unwrap()),
                ..Default::default()
            })
        );
    }

    #[rstest]
    #[case("some-invalid_string")] // DID does not start from 'did:web'
    #[case("did:web:-example.com")] // domain name starts from hyphen
    #[case("did:web:test%example.com")] // prohibited symbol in domain name
    #[case("did:web:test..example.com")] // invalid domain name parts separator
    #[case("did:web:example.com3Avvv")] // invalid non-digit port value
    #[case("did:web:example.com:us$ers")] // prohibited symbol in the path segment
    #[case("did:web:example.com:users::alice")] // empty path segment between two ':'
    #[tokio::test]
    async fn did_doc_generating_fails_when_did_is_not_valid(#[case] invalid_did: &str) {
        let kms = crate::inmem::kms::LocalKms::new();
        let (_, key) = kms
            .create_and_handle(KeyType::Ed25519, kms::CreateOptions {})
            .await
            .unwrap();

        println!("{invalid_did}");
        let result = DIDWeb::generate_did_document(invalid_did, &key);

        assert!(matches!(
            result.err().unwrap(),
            Error::InvalidDidFormat { .. }
        ));
    }
}
