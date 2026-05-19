//! did:web method.

use crate::crypto::JWK;
use crate::did::universal::DIDResolver;
use crate::did::{
    DID, DIDDoc, DidBufCreationSnafu, DidDocGenerationSnafu, DidGenerationSnafu,
    DidUrlBufCreationSnafu, InvalidDidFormatSnafu, IriRefCreationSnafu, KeyNotSupportedSnafu,
    ParseSnafu, ResolutionOutput, Result, VerificationMethodKey, VerificationRelationshipType,
};
use crate::http::HttpClient;
use crate::utils::http::MIME_TYPE_JSON;
use async_trait::async_trait;
use iref::uri::AuthorityBuf;
use oauth2::http::{Method, Request, Uri, header};
use regex::Regex;
use serde_json::Value;
use snafu::ResultExt;
use ssi::dids::document::DIDVerificationMethod;
use ssi::dids::document::representation::MediaType;
use ssi::dids::document::representation::json_ld::DIDContext;
use ssi::dids::document::verification_method::ValueOrReference;
use ssi::dids::resolution::{Error, Options, Output};
use ssi::dids::ssi_json_ld::syntax::ContextEntry;
use ssi::dids::{DIDBuf, DIDMethod, DIDURLBuf, DIDURLReferenceBuf, Document};
use ssi::json_ld::IriRefBuf;
use ssi::jwk::Params;
use ssi::security::MultibaseBuf;
use ssi::security::multibase::Base;
use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{Level, instrument};
use url::Url;

type Level_ = Level;

const ED25519_VM_TYPE: &str = "Ed25519VerificationKey2018";
const ED25519_VM_TYPE_IRI: &str = "https://w3id.org/security#Ed25519VerificationKey2018";
const ECDSASECP256K1_VM_TYPE: &str = "EcdsaSecp256k1VerificationKey2019";
const ECDSASECP256K1_VM_TYPE_IRI: &str =
    "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019";
const ECDSASECP256R1_VM_TYPE: &str = "EcdsaSecp256r1VerificationKey2019";
const ECDSASECP256R1_VM_TYPE_IRI: &str =
    "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019";

// ([a-z0-9][a-z0-9\-]*)      first part of domain name
// (\.[a-z0-9][a-z0-9\-]*)*   any number of domain name parts
// (%3A[0-9]+)?               optional port segment
// (:[A-Za-z0-9_\-\.]+)*      any number of path segments
const DID_WEB_PATTERN: &str =
    r"^did:web:([a-z0-9][a-z0-9\-]*)(\.[a-z0-9][a-z0-9\-]*)*(%3A[0-9]+)?(:[A-Za-z0-9_\-\.]+)*$";

/// Resolver for the `did:web` method.
///
/// Supports generation of `did:web`.
pub struct DIDWeb {
    http_client: Arc<dyn HttpClient>,
}

impl DIDWeb {
    /// Creates a new instance of `did:web` resolver
    ///
    /// # Parameters
    /// - `http_client`: Http client that implements the `HttpClient` trait.
    ///
    /// # Returns
    /// An instance of the struct with the provided `http_client` set.
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        Self { http_client }
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
            .ok_or_else(|| {
                DidGenerationSnafu {
                    details: "invalid url: path segments are not specified",
                }
                .build()
            })?
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
    /// - `keys`: [VerificationMethodKey] objects representing the cryptographic keys
    ///   that will be embedded in the DID document.
    ///
    /// # Returns
    ///
    /// A new [DIDDoc].
    ///
    /// # Errors
    ///
    /// * [crate::did::Error::KeyNotSupported] - key type is not supported.
    #[instrument(level = Level::TRACE, skip(keys), err(), ret())]
    pub fn generate_did_document(did: &str, keys: &[VerificationMethodKey]) -> Result<DIDDoc> {
        validate_didweb(did)?;

        let mut document = Document::new(DIDBuf::from_str(did).context(DidBufCreationSnafu)?);
        let mut vm_type_iris = HashSet::new();
        for (index, key) in keys.iter().enumerate() {
            let jwk = Self::validate_jwk_key(key)?;
            let (vm_type, vm_type_iri, (public_key_name, public_key_value)) =
                Self::extract_verification_method_params(&jwk)?;
            vm_type_iris.insert(vm_type_iri);

            Self::add_verification_method(
                did,
                index,
                (vm_type, (public_key_name, public_key_value)),
                &key.verification_relationships,
                &mut document,
            )?;
        }

        let context_entries = vm_type_iris
            .iter()
            .map(|iri_ref| ContextEntry::IriRef(iri_ref.to_owned()))
            .collect();
        let options = ssi::dids::document::representation::Options::JsonLd({
            ssi::dids::document::representation::json_ld::Options {
                context: ssi::dids::document::representation::json_ld::Context::array(
                    DIDContext::V1,
                    context_entries,
                ),
            }
        });
        Ok(DIDDoc::new(document, options))
    }

    fn validate_jwk_key(verification_method_key: &VerificationMethodKey) -> Result<JWK> {
        let jwk = verification_method_key.key.jwk().ok_or_else(|| {
            DidDocGenerationSnafu {
                details: "the key does not support JWK form",
            }
            .build()
        })?;
        Ok(jwk)
    }

    fn add_verification_method(
        did: &str,
        index: usize,
        (vm_type, (public_key_name, public_key_value)): (&str, (String, Value)),
        verification_relationships: &HashSet<VerificationRelationshipType>,
        construction_did_doc: &mut Document,
    ) -> Result<()> {
        let mut properties = BTreeMap::new();
        properties.insert(public_key_name, public_key_value);
        let verification_method = DIDVerificationMethod {
            id: DIDURLBuf::from_string(format!("{}#key-{}", did, index))
                .context(DidUrlBufCreationSnafu)?,
            type_: vm_type.to_string(),
            controller: DIDBuf::from_str(did).context(DidBufCreationSnafu)?,
            properties,
        };

        for verification_relationship in verification_relationships {
            let did_url_buf = ValueOrReference::Reference(DIDURLReferenceBuf::Absolute(
                verification_method.id.clone(),
            ));
            match verification_relationship {
                VerificationRelationshipType::Authentication => {
                    construction_did_doc
                        .verification_relationships
                        .authentication
                        .push(did_url_buf);
                }
                VerificationRelationshipType::Assertion => {
                    construction_did_doc
                        .verification_relationships
                        .assertion_method
                        .push(did_url_buf);
                }
                VerificationRelationshipType::KeyAgreement => {
                    // TODO: Create Verification Method with the type X25519KeyAgreementKey2020 for ED25519
                    construction_did_doc
                        .verification_relationships
                        .key_agreement
                        .push(did_url_buf);
                }
                VerificationRelationshipType::CapabilityInvocation => {
                    construction_did_doc
                        .verification_relationships
                        .capability_invocation
                        .push(did_url_buf);
                }
                VerificationRelationshipType::CapabilityDelegation => {
                    construction_did_doc
                        .verification_relationships
                        .capability_delegation
                        .push(did_url_buf);
                }
            }
        }
        construction_did_doc
            .verification_method
            .push(verification_method);

        Ok(())
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    fn extract_verification_method_params(jwk: &JWK) -> Result<(&str, IriRefBuf, (String, Value))> {
        let result = match jwk.params {
            Params::OKP(ref params) => match &params.curve[..] {
                "Ed25519" => {
                    let key = bs58::encode(&params.public_key.0).into_string();
                    (
                        ED25519_VM_TYPE,
                        IriRefBuf::new(ED25519_VM_TYPE_IRI.to_string())
                            .context(IriRefCreationSnafu)?,
                        ("publicKeyBase58".to_string(), Value::String(key)),
                    )
                }
                _ => {
                    return KeyNotSupportedSnafu {
                        type_: params.curve.clone(),
                    }
                    .fail();
                }
            },
            Params::EC(ref params) => match params.curve {
                Some(ref curve) => match &curve[..] {
                    "secp256k1" => (
                        ECDSASECP256K1_VM_TYPE,
                        IriRefBuf::new(ECDSASECP256K1_VM_TYPE_IRI.to_string())
                            .context(IriRefCreationSnafu)?,
                        (
                            "publicKeyJwk".to_string(),
                            serde_json::to_value(jwk).context(ParseSnafu)?,
                        ),
                    ),
                    "secp256r1" | "P-256" => {
                        let key = MultibaseBuf::encode(
                            Base::Base58Btc,
                            jwk.to_multicodec()
                                .map_err(|e| {
                                    DidDocGenerationSnafu {
                                        details: format!(
                                            "could not convert jwk to multicodec form: {e}"
                                        ),
                                    }
                                    .build()
                                })?
                                .as_bytes(),
                        );
                        (
                            ECDSASECP256R1_VM_TYPE,
                            IriRefBuf::new(ECDSASECP256R1_VM_TYPE_IRI.to_string())
                                .context(IriRefCreationSnafu)?,
                            (
                                "publicKeyMultibase".to_string(),
                                serde_json::to_value(key).context(ParseSnafu)?,
                            ),
                        )
                    }
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

        Ok(result)
    }
}

fn validate_didweb(did: &str) -> Result<()> {
    let re = Regex::new(DID_WEB_PATTERN).unwrap();

    if !re.is_match(did) {
        return InvalidDidFormatSnafu { details: did }.fail();
    }

    Ok(())
}

impl DIDMethod for DIDWeb {
    const DID_METHOD_NAME: &'static str = "web";
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDWeb {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a ssi::dids::DID,
        _: Options,
    ) -> std::result::Result<ResolutionOutput, Error> {
        let url = did_web_to_uri(did.method_specific_id())?;
        let request = Request::head(url)
            .header(header::ACCEPT, MIME_TYPE_JSON)
            .method(Method::GET)
            .body(vec![])
            .map_err(|err| Error::Internal(format!("Could not build http request: {}", err)))?;

        let resp = self.http_client.async_call(request).await.map_err(|err| {
            Error::Internal(format!(
                "Could not fetch did document of = {}: {}",
                did, err
            ))
        })?;

        let did_doc = serde_json::from_slice(resp.body())
            .map_err(|e| Error::Internal(format!("Could not parse did document: {}", e)))?;

        Ok(Output::from_content(
            did_doc,
            Some(MediaType::Json.to_string()),
        ))
    }

    fn method_name(&self) -> String {
        Self::DID_METHOD_NAME.to_string()
    }
}

fn did_web_to_uri(id: &str) -> std::result::Result<Uri, Error> {
    let mut parts = id.split(':').peekable();

    // Extract the authority, with an optional port colon percent-encoded.
    let encoded_authority = parts
        .next()
        .ok_or_else(|| Error::InvalidMethodSpecificId(id.to_owned()))?;

    // Decode authority.
    let authority: AuthorityBuf = match encoded_authority.rsplit_once("%3A") {
        Some((host, port)) => AuthorityBuf::new(format!("{host}:{port}").into_bytes())
            .map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))?,
        None => encoded_authority
            .parse()
            .map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))?,
    };

    // Resolve what scheme to use.
    let host = authority.host().as_str();
    let scheme = if host == "localhost" {
        "http"
    } else {
        match Ipv4Addr::from_str(host) {
            Ok(ip) if ip.is_private() || ip.is_loopback() => "http",
            Ok(_) => return Err(Error::InvalidMethodSpecificId(id.to_owned())),
            _ => "https",
        }
    };

    let path = match parts.peek() {
        Some(_) => parts.collect::<Vec<&str>>().join("/"),
        None => ".well-known".to_string(),
    };

    let url = format!("{scheme}://{authority}/{path}/did.json");

    Uri::from_str(&url).map_err(|e| Error::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Key;
    use crate::did::Error;
    use crate::http::MockHttpClient;
    use crate::kms;
    use crate::kms::KeyType;
    use crate::kms::Kms;
    use crate::utils::http::test::mock_http_once;
    use crate::utils::test_utils::no_jwk_key;
    use http::StatusCode;
    use rstest::rstest;
    use serde_json::json;
    use ssi::dids::did;

    const DID_JSON: &str = r#"{
      "@context": "https://www.w3.org/ns/did/v1",
      "id": "did:web:test.example.com",
      "verificationMethod": [{
         "id": "did:web:test.example.com#key0",
         "type": "Ed25519VerificationKey2018",
         "controller": "did:web:test.example.com",
         "publicKeyBase58": "2sXRz2VfrpySNEL6xmXJWQg6iY94qwNp1qrJJFBuPWmH"
      }],
      "assertionMethod": ["did:web:test.example.com#key0"]
    }"#;

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

    #[tokio::test]
    async fn did_doc_is_generated_correctly() {
        let did = "did:web:test.example.com";
        let expected_did_doc_without_context = |random1: &str, random2: &str| -> Value {
            json!({
                "id": did,
                "keyAgreement": [
                    "did:web:test.example.com#key-0",
                    "did:web:test.example.com#key-1",
                ],
                "verificationMethod": [
                     {
                        "id": "did:web:test.example.com#key-0",
                        "type": ECDSASECP256R1_VM_TYPE,
                        "controller": did,
                        "publicKeyMultibase": random1,
                    },
                    {
                        "id": "did:web:test.example.com#key-1",
                        "type": ED25519_VM_TYPE,
                        "controller": did,
                        "publicKeyBase58": random2,
                    },
                ],
            })
        };

        let kms = crate::inmem::kms::LocalKms::new();
        let (_, key_handle_p256) = kms
            .create_and_handle(KeyType::P256, kms::CreateOptions::default())
            .await
            .unwrap();
        let (_, key_handle_ed25519) = kms
            .create_and_handle(KeyType::Ed25519, kms::CreateOptions::default())
            .await
            .unwrap();
        let key_p256: &dyn Key = &key_handle_p256;
        let key_ed25519: &dyn Key = &key_handle_ed25519;
        let keys = vec![
            VerificationMethodKey {
                key: key_p256,
                verification_relationships: HashSet::from_iter([
                    VerificationRelationshipType::KeyAgreement,
                ]),
            },
            VerificationMethodKey {
                key: key_ed25519,
                verification_relationships: HashSet::from_iter([
                    VerificationRelationshipType::KeyAgreement,
                ]),
            },
        ];
        let did_doc = DIDWeb::generate_did_document(did, &keys).unwrap();
        let mut actual_did_doc_value = serde_json::to_value(&did_doc).unwrap();
        let public_key_multibase =
            actual_did_doc_value["verificationMethod"][0]["publicKeyMultibase"]
                .as_str()
                .unwrap();
        let public_key_base58 = actual_did_doc_value["verificationMethod"][1]["publicKeyBase58"]
            .as_str()
            .unwrap();
        let expected_did_doc_value =
            expected_did_doc_without_context(public_key_multibase, public_key_base58);

        let binding = actual_did_doc_value
            .as_object_mut()
            .unwrap()
            .remove("@context")
            .unwrap();
        let actual_context = binding.as_array().unwrap();
        assert!(
            actual_context.contains(&serde_json::to_value("https://www.w3.org/ns/did/v1").unwrap())
        );
        assert!(
            actual_context.contains(&serde_json::to_value(ECDSASECP256R1_VM_TYPE_IRI).unwrap())
        );
        assert!(actual_context.contains(&serde_json::to_value(ED25519_VM_TYPE_IRI).unwrap()));
        assert_eq!(actual_did_doc_value, expected_did_doc_value);
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
        let (_, key_handle) = kms
            .create_and_handle(KeyType::Ed25519, kms::CreateOptions::default())
            .await
            .unwrap();

        let key: &dyn Key = &key_handle;
        let keys = vec![VerificationMethodKey {
            key,
            verification_relationships: Default::default(),
        }];
        let result = DIDWeb::generate_did_document(invalid_did, &keys);

        assert!(matches!(
            result.err().unwrap(),
            Error::InvalidDidFormat { .. }
        ));
    }

    #[tokio::test]
    async fn did_doc_generating_fails_on_invalid_jwk() {
        let did = "did:web:test.example.com";
        let binding = no_jwk_key();
        let verification_method_keys = vec![VerificationMethodKey {
            key: &binding,
            verification_relationships: Default::default(),
        }];
        let result = DIDWeb::generate_did_document(did, &verification_method_keys);

        assert!(matches!(
            result.err().unwrap(),
            Error::DidDocGeneration { .. }
        ));
    }

    #[tokio::test]
    async fn did_doc_generates_all_five_verification_relationships() {
        let did = "did:web:test.example.com";
        let kms = crate::inmem::kms::LocalKms::new();
        let (_, kh) = kms
            .create_and_handle(KeyType::Ed25519, kms::CreateOptions::default())
            .await
            .unwrap();
        let key: &dyn Key = &kh;

        let keys = vec![VerificationMethodKey {
            key,
            verification_relationships: HashSet::from_iter([
                VerificationRelationshipType::Authentication,
                VerificationRelationshipType::Assertion,
                VerificationRelationshipType::KeyAgreement,
                VerificationRelationshipType::CapabilityInvocation,
                VerificationRelationshipType::CapabilityDelegation,
            ]),
        }];

        let did_doc = DIDWeb::generate_did_document(did, &keys).unwrap();
        let value = serde_json::to_value(&did_doc).unwrap();

        // Each relationship should reference the single verification method id.
        let vm_id = "did:web:test.example.com#key-0";
        for rel in [
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            let arr = value[rel]
                .as_array()
                .unwrap_or_else(|| panic!("expected array for relationship {rel}, got {value:?}"));
            assert_eq!(arr.len(), 1, "expected one reference under {rel}");
            assert_eq!(arr[0].as_str().unwrap(), vm_id);
        }
    }

    #[tokio::test]
    async fn did_doc_resolving_works() {
        let mut http_client = MockHttpClient::new();

        mock_http_once(
            &mut http_client,
            Method::GET,
            Url::parse("https://test.example.com/.well-known/did.json").unwrap(),
            serde_json::from_str::<Value>(DID_JSON).unwrap(),
            StatusCode::OK,
        );

        let resolver = DIDWeb::new(Arc::new(http_client));

        let did_doc_expected = Document::from_bytes(MediaType::Json, DID_JSON.as_bytes()).unwrap();
        let did_doc = resolver
            .resolve_representation(did!("did:web:test.example.com"), Options::default())
            .await
            .unwrap()
            .document;

        assert_eq!(did_doc.document(), did_doc_expected.document());
    }
}
