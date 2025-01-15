use crate::crypto::{Key, JWK};
use crate::did::{
    DIDDoc, DidBufCreationSnafu, DidDocGenerationSnafu, DidGenerationSnafu, DidUrlBufCreationSnafu,
    InvalidDidFormatSnafu, IriRefCreationSnafu, KeyNotSupportedSnafu, ParseSnafu, Result, DID,
};
use regex::Regex;
use snafu::ResultExt;
use ssi::dids::document::representation::json_ld::DIDContext;
use ssi::dids::document::verification_method::ValueOrReference;
use ssi::dids::ssi_json_ld::syntax::ContextEntry;
use ssi::dids::{DIDBuf, DIDURLBuf, DIDURLReferenceBuf, Document};
use ssi::json_ld::IriRefBuf;
use ssi::jwk::Params;
use ssi::security::multibase::Base;
use ssi::security::MultibaseBuf;
use std::collections::BTreeMap;
use std::str::FromStr;
use tracing::{instrument, Level};
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
pub struct DIDWeb {}

impl DIDWeb {
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

        let (vm_type, vm_type_iri, (public_key_name, public_key_value)) =
            Self::extract_verification_method_params(&jwk)?;

        let mut document = Document::new(DIDBuf::from_str(did).context(DidBufCreationSnafu)?);

        let array = vec![ContextEntry::IriRef(vm_type_iri)];
        let mut properties = BTreeMap::new();
        properties.insert(public_key_name, public_key_value);
        let default_vm = ssi::dids::document::DIDVerificationMethod {
            id: DIDURLBuf::from_string(format!("{}#key-0", did)).context(DidUrlBufCreationSnafu)?,
            type_: vm_type.to_string(),
            controller: DIDBuf::from_str(did).context(DidBufCreationSnafu)?,
            properties,
        };

        let did_url_buf = default_vm.id.clone();

        document.verification_method = vec![default_vm];

        document.verification_relationships.assertion_method = vec![ValueOrReference::Reference(
            DIDURLReferenceBuf::Absolute(did_url_buf),
        )];

        let options = ssi::dids::document::representation::Options::JsonLd({
            ssi::dids::document::representation::json_ld::Options {
                context: ssi::dids::document::representation::json_ld::Context::array(
                    DIDContext::V1,
                    array,
                ),
            }
        });

        let did_doc = DIDDoc::new(document, options);

        Ok(did_doc)
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    fn extract_verification_method_params(
        jwk: &JWK,
    ) -> Result<(&str, IriRefBuf, (String, serde_json::Value))> {
        let result = match jwk.params {
            Params::OKP(ref params) => match &params.curve[..] {
                "Ed25519" => {
                    let key = bs58::encode(&params.public_key.0).into_string();
                    (
                        ED25519_VM_TYPE,
                        IriRefBuf::new(ED25519_VM_TYPE_IRI.to_string())
                            .context(IriRefCreationSnafu)?,
                        (
                            "publicKeyBase58".to_string(),
                            serde_json::Value::String(key),
                        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::Error;
    use crate::kms;
    use crate::kms::KeyType;
    use crate::kms::Kms;
    use crate::utils::test_utils::no_jwk_key;
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
    #[case::p256((KeyType::P256, ECDSASECP256R1_VM_TYPE,ECDSASECP256R1_VM_TYPE_IRI))]
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
            serde_json::to_value(&did_doc)
                .unwrap()
                .get("@context")
                .unwrap()
                .to_owned(),
            serde_json::to_value(json!(["https://www.w3.org/ns/did/v1", vm_type_iri])).unwrap()
        );

        assert_eq!(did_doc.id, did);

        assert_eq!(
            did_doc.verification_method[0].id,
            DIDURLBuf::new(format!("{did}#key-0").as_bytes().to_vec()).unwrap()
        );
        assert_eq!(did_doc.verification_method[0].type_, vm_type.to_string());
        assert_eq!(
            did_doc.verification_method[0].controller,
            DIDBuf::from_str(did).unwrap()
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

        let result = DIDWeb::generate_did_document(invalid_did, &key);

        assert!(matches!(
            result.err().unwrap(),
            Error::InvalidDidFormat { .. }
        ));
    }

    #[tokio::test]
    async fn did_doc_generating_fails_on_invalid_jwk() {
        let did = "did:web:test.example.com";
        let result = DIDWeb::generate_did_document(did, &no_jwk_key());

        assert!(matches!(
            result.err().unwrap(),
            Error::DidDocGeneration { .. }
        ));
    }
}
