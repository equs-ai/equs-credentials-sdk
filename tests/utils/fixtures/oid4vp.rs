use crate::utils::helpers::create_did_keymetadata_keyhandle;
use agent_sdk::did::DIDURL;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::inmem::kms::{KeyHandle, LocalKms};
use agent_sdk::nonce::{Nonce, NonceHandler};
use agent_sdk::vc::claims::{Claim, Claims};
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::dcql::{DCQL, DCQLCredential};
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::presentation_exchange::PresentationDefinition;
use agent_sdk::vc::{
    Credential, CredentialMetadata, JsonLdAPIVCMetadata, VCFormatsAPI, VCFormatsJsonLdAPI,
    VCFormatsSdJwtAPI, VCMetadata,
};
use agent_sdk::{crypto, nonce};
use async_trait::async_trait;
use openid4vp::core::input_descriptor::InputDescriptor;
use openid4vp::utils::NonEmptyVec;
use serde_json::json;
use ssi::dids::ssi_json_ld::IriRefBuf;
use std::str::FromStr;

pub type ValidateClaimsFunc = dyn Fn(Claims) + Send + Sync;
pub const NONCE: &str = "some_nonce";

pub enum Oid4VpTestCredentialFormat {
    SdJwt(VCMetadata),
    LdpVc(Box<JsonLdAPIVCMetadata>),
}

pub struct Oid4VpTestCredential {
    pub format: Oid4VpTestCredentialFormat,
    pub claims: Claims,
}

pub struct Oid4VpTestCase {
    pub credentials: Vec<Oid4VpTestCredential>,
    pub presentation_definition: PresentationDefinition,
    pub dcql: Option<DCQL>,
    pub validate: Box<ValidateClaimsFunc>,
}

pub const VERIFIER_URL: &str = "http://example.com";
pub const STATE: &str = "d7a4bdce-d46f-48b3-ad85-4fcc5e124ad8";

fn sample_jsonld_resident_card_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let format = Oid4VpTestCredentialFormat::LdpVc(Box::new(
        JsonLdAPIVCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec![
                "VerifiableCredential".to_string(),
                "PermanentResident".to_string(),
            ],
            Some(time::Duration::days(5 * 365)),
        )
        .unwrap(),
    ));

    let credential = Oid4VpTestCredential {
        format,
        claims: json!({
            "type": ["PermanentResident", "Person"],
            "givenName": "John",
            "familyName": "Doe",
            "birthDate": "09/09/1989",
        })
        .try_into()
        .unwrap(),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "residentCard",
            "name": "Identity VC",
            "purpose": "We want an identity",
            "format": {
                "ldp_vc": {
                   "proof_type": [
                    "Ed25519Signature2018",
                    "EcdsaSecp256k1Signature2019"
                   ]
                }
            },
            "constraints": {
                "fields": [
                    {
                        "path": ["$.type"],
                        "filter": {
                            "type": "array",
                            "contains": {
                                "const": "PermanentResident"
                            },
                        }
                    }
                ]
            }
        }
    ))
    .unwrap();

    (credential, input_descriptor)
}

pub fn sample_dcql_query_ldp_vc() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!(
                  {
                      "id": "residentCard",
                      "format": "ldp_vc",
                      "meta": {},
                  }
    ))
    .unwrap();

    DCQL::new(vec![desc].try_into().unwrap())
}

pub fn sample_dcql_query_sdjwt() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!(
        {
            "id": "identity",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [
                {
                    "path": [
                        "name"
                    ]
                }
            ]
        }
    ))
    .unwrap();

    DCQL::new(vec![desc].try_into().unwrap())
}

fn sample_sdjwt_identity_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let format = Oid4VpTestCredentialFormat::SdJwt(VCMetadata {
        vct: "https://credentials.example.com/identity_credential".to_owned(),
        lifetime: Some(time::Duration::days(365)),
        disclosures: vec![
            "$.name".to_owned(),
            "$.surname".to_owned(),
            "$.address".to_owned(),
        ],
        credential_status: None,
    });

    let credential = Oid4VpTestCredential {
        format,
        claims: json!({
            "name": "John",
            "surname": "Doe",
            "address": "221B Baker Street",
            "date": "09/09/1989",
        })
        .try_into()
        .unwrap(),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "identity",
            "name": "Identity VC",
            "purpose": "We want an identity",
            "format": {
                "dc+sd-jwt": {
                   "sd-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                   ],
                   "kb-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                   ]
                }
             },
            "constraints": {
                "fields": [
                    {
                        "path": ["$.vct"],
                        "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/identity_credential"
                        }
                    },
                    {
                        "path": ["$.name"]
                    }
                ]
            }
        }
    ))
    .unwrap();

    (credential, input_descriptor)
}

fn sample_sdjwt_degree_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let format = Oid4VpTestCredentialFormat::SdJwt(VCMetadata {
        vct: "https://credentials.example.com/degree_credential".to_owned(),
        lifetime: Some(time::Duration::days(365)),
        disclosures: vec![
            "$.name".to_owned(),
            "$.surname".to_owned(),
            "$.address".to_owned(),
        ],
        credential_status: None,
    });

    let credential = Oid4VpTestCredential {
        format,
        claims: json!({
            "name": "John",
            "surname": "Doe",
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science and Arts"
            },
            "date": "09/09/2002",
        })
        .try_into()
        .unwrap(),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "Degree1",
            "name": "Degree VC",
            "format": {
                "dc+sd-jwt": {
                   "sd-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                   ],
                   "kb-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                   ]
                }
             },
            "constraints": {
                "fields": [
                    {
                        "path": ["$.vct"],
                        "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/degree_credential"
                        }
                    },
                    {
                        "path": ["$.name"]
                    }
                ]
            }
        }
    ))
    .unwrap();

    (credential, input_descriptor)
}

pub fn single_jsonld_presentation_case() -> Oid4VpTestCase {
    let (credential, descriptor) = sample_jsonld_resident_card_credential();
    let dcql = sample_dcql_query_ldp_vc();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor,
    );

    let validate: Box<ValidateClaimsFunc> = Box::new(|vp_response| {
        let presentations = extract_vp_claims(vp_response, "residentCard");

        assert_eq!(presentations.len(), 1);
        let presentation = &presentations[0];
        assert_eq!(
            presentation["verifiableCredential"]["credentialSubject"]["givenName"],
            Claim::String("John".to_string())
        );
        assert_eq!(
            presentation["verifiableCredential"]["credentialSubject"]["familyName"],
            Claim::String("Doe".to_string())
        );
        assert_eq!(
            presentation["verifiableCredential"]["credentialSubject"]["birthDate"],
            Claim::String("09/09/1989".to_string())
        );
    });

    Oid4VpTestCase {
        credentials: vec![credential],
        presentation_definition,
        validate,
        dcql: Some(dcql),
    }
}

pub fn single_sdjwt_presentation_case() -> Oid4VpTestCase {
    let (credential, descriptor) = sample_sdjwt_identity_credential();
    let dcql = sample_dcql_query_sdjwt();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor,
    );

    let validate: Box<ValidateClaimsFunc> = Box::new(|vp_response| {
        let presentations = extract_vp_claims(vp_response, "identity");
        assert_eq!(presentations.len(), 1);
        let presentation = &presentations[0];

        assert_eq!(
            &presentation["vct"],
            &Claim::String("https://credentials.example.com/identity_credential".to_string())
        );
        assert_eq!(&presentation["name"], &Claim::String("John".to_string()));
    });

    Oid4VpTestCase {
        credentials: vec![credential],
        presentation_definition,
        validate,
        dcql: Some(dcql),
    }
}

pub fn presentation_exchange_multiple_sdjwt_presentation_case() -> Oid4VpTestCase {
    let (cred_identity, descriptor_identity) = sample_sdjwt_identity_credential();
    let (cred_degree, descriptor_degree) = sample_sdjwt_degree_credential();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor_identity,
    )
    .add_input_descriptor(descriptor_degree);

    let validate: Box<ValidateClaimsFunc> = Box::new(|vp_response| {
        let mut presentations = extract_vp_claims(vp_response.clone(), "identity");
        assert_eq!(presentations.len(), 1);
        assert_eq!(
            &presentations[0]["vct"],
            &Claim::String("https://credentials.example.com/identity_credential".to_string())
        );
        assert_eq!(
            &presentations[0]["name"],
            &Claim::String("John".to_string())
        );

        presentations = extract_vp_claims(vp_response, "Degree1");
        assert_eq!(presentations.len(), 1);
        assert_eq!(
            &presentations[0]["vct"],
            &Claim::String("https://credentials.example.com/degree_credential".to_string())
        );
        assert_eq!(
            &presentations[0]["degree"]["type"],
            &Claim::String("BachelorDegree".to_string())
        );
    });

    Oid4VpTestCase {
        credentials: vec![cred_identity, cred_degree],
        presentation_definition,
        validate,
        dcql: None,
    }
}

pub fn dcql_multiple_sdjwt_presentation_case() -> Oid4VpTestCase {
    let (cred_identity_1, descriptor_identity_1) = sample_sdjwt_identity_credential();
    let (cred_identity_2, descriptor_identity_2) = sample_sdjwt_identity_credential();
    let (cred_degree, descriptor_degree) = sample_sdjwt_degree_credential();
    let dcql = sample_dcql_query_for_multiple_sdjwt();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor_degree,
    )
    .add_input_descriptor(descriptor_identity_1)
    .add_input_descriptor(descriptor_identity_2);

    let validate: Box<ValidateClaimsFunc> = Box::new(|vp_response| {
        // Check the first claims with 'multiple' set to true
        let mut presentations = extract_vp_claims(vp_response.clone(), "identity_1");
        assert_eq!(presentations.len(), 2);
        assert_eq!(
            &presentations[0]["vct"],
            &Claim::String("https://credentials.example.com/identity_credential".to_string())
        );
        assert_eq!(
            &presentations[0]["name"],
            &Claim::String("John".to_string())
        );

        assert_eq!(
            &presentations[1]["vct"],
            &Claim::String("https://credentials.example.com/identity_credential".to_string())
        );
        assert_eq!(
            &presentations[1]["surname"],
            &Claim::String("Doe".to_string())
        );

        // Check the second claims with 'multiple' set to false
        presentations = extract_vp_claims(vp_response.clone(), "identity_2");
        assert_eq!(presentations.len(), 1);
        assert_eq!(
            &presentations[0]["name"],
            &Claim::String("John".to_string())
        );

        // Check the third claims without 'multiple'
        presentations = extract_vp_claims(vp_response, "Degree1");
        assert_eq!(presentations.len(), 1);
        assert_eq!(
            &presentations[0]["vct"],
            &Claim::String("https://credentials.example.com/degree_credential".to_string())
        );
        assert_eq!(
            &presentations[0]["degree"]["type"],
            &Claim::String("BachelorDegree".to_string())
        );
    });

    Oid4VpTestCase {
        credentials: vec![cred_identity_1, cred_identity_2, cred_degree],
        presentation_definition,
        validate,
        dcql: Some(dcql),
    }
}

pub fn sample_dcql_query_for_multiple_sdjwt() -> DCQL {
    let desc1: DCQLCredential = serde_json::from_value(json!(
                  {
                      "id": "identity_1",
                      "format": "dc+sd-jwt",
                      "meta": {},
                      "claims": [
                        {"path": ["name"]},
                        {"path": ["surname"]},
                        {
                            "path": ["vct"],
                            "values": ["https://credentials.example.com/identity_credential"]
                        },
                      ],
                      "multiple": true
                  }
    ))
    .unwrap();
    let desc2: DCQLCredential = serde_json::from_value(json!(
                  {
                      "id": "identity_2",
                      "format": "dc+sd-jwt",
                      "meta": {},
                      "claims": [
                        {"path": ["name"]},
                      ],
                      "multiple": false
                  }
    ))
    .unwrap();

    let desc3: DCQLCredential = serde_json::from_value(json!(
      {
          "id": "Degree1",
          "format": "dc+sd-jwt",
          "meta": {},
          "claims": [
            {
              "path": [
                "name"
              ]
            },
            {
              "path": [
                "vct"
              ],
              "values": [
                "https://credentials.example.com/degree_credential"
              ]
            }
          ]
      }
    ))
    .unwrap();

    DCQL::new(vec![desc1, desc2, desc3].try_into().unwrap())
}

fn extract_vp_claims(vp_response: Claims, vp_name: &str) -> Vec<Claims> {
    let Claim::Array(ref presentations) = vp_response["vp_token"][vp_name] else {
        panic!("Expected array of claims");
    };
    let mut claims: Vec<Claims> = vec![];
    for presentation in presentations {
        let Claim::Object(claim) = presentation else {
            panic!("Expected object of claims");
        };

        claims.push(Claims::from_map(claim.clone()))
    }

    claims
}

#[derive(Default)]
pub struct MockNonceHandler {}

#[async_trait]
impl NonceHandler for MockNonceHandler {
    async fn generate(&self) -> nonce::Result<Nonce> {
        Ok(Nonce::from_secret(NONCE.to_string()))
    }

    async fn validate(&self, _nonce: &Nonce) -> nonce::Result<bool> {
        Ok(true)
    }
}

pub(crate) async fn create_vc(
    format: Oid4VpTestCredentialFormat,
    holder_did_url: &str,
    holder_kid: String,
    holder_kh: impl crypto::Key,
    claims: Claims,
) -> (Credential, CredentialMetadata) {
    println!("claims: {:?}", claims);

    // Generate Issuer DID and Key
    let kms = LocalKms::new();
    let (did, key_metadata, kh) = create_did_keymetadata_keyhandle(&kms).await;
    println!("Issuer DID: {}", did);

    match format {
        Oid4VpTestCredentialFormat::SdJwt(metadata) => {
            let vc = VCFormatsSdJwtAPI::create_vc(
                claims.clone(),
                (DIDURL::new(&key_metadata.did_url).unwrap(), kh),
                (DIDURL::new(holder_did_url).unwrap(), holder_kh),
                metadata,
                UniversalResolver::default(),
            )
            .await
            .unwrap();

            println!("Credential: {}", vc);

            let credential = Credential::SdJwt(vc);
            let metadata = DefaultMetadataProcessor::resolve_metadata(
                &credential,
                KeyMetadata {
                    did_url: holder_did_url.to_string(),
                    kid: holder_kid,
                },
            )
            .unwrap();

            (credential, metadata)
        }
        Oid4VpTestCredentialFormat::LdpVc(metadata) => {
            let vc = VCFormatsJsonLdAPI::create_vc(
                claims,
                (DIDURL::new(&key_metadata.did_url).unwrap(), kh),
                (DIDURL::new(holder_did_url).unwrap(), holder_kh),
                *metadata,
                UniversalResolver::default(),
            )
            .await
            .unwrap();

            println!("Credential: {}", serde_json::to_string_pretty(&vc).unwrap());

            let credential = Credential::LdpVc(vc);
            let metadata = DefaultMetadataProcessor::resolve_metadata(
                &credential,
                KeyMetadata {
                    did_url: holder_did_url.to_string(),
                    kid: holder_kid,
                },
            )
            .unwrap();

            (credential, metadata)
        }
    }
}

pub(crate) async fn generate_did_key_and_vm(kms: &LocalKms) -> (KeyMetadata, KeyHandle) {
    let (_, key_md, key_handle) = create_did_keymetadata_keyhandle(kms).await;

    (key_md, key_handle)
}

pub(crate) fn sample_dcql_query_for_mso_mdoc_vp_request() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!(
        {
            "id": "mDL",
            "format": "mso_mdoc",
            "meta": {
                "doctype_value": "org.iso.18013.5.1.mDL"
            },
            "claims": [
                {
                    "path": ["org.iso.18013.5.1", "given_name"],
                    "path": ["org.iso.18013.5.1", "family_name"],
                },
            ],
        }
    ))
    .unwrap();

    DCQL::new(NonEmptyVec::new(desc))
}
// Generated by one-core/src/provider/credential_formatter/mdoc_formatter/test.rs::generate_asdk_sample_mdl_vp_for_e2e
// Certificates have no CRL distribution points and are valid for 10 years.
// To regenerate: run `cargo test -p one-core --features mock generate_asdk_sample_mdl_vp_for_e2e -- --ignored --nocapture` in one-core-new
pub const SAMPLE_MDL_VP_TOKEN: &str = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWGqkaGRpZ2VzdElEAGZyYW5kb21YIKTc4Edaqzy5U5ONrjqPET4MvHfPF4v69APJ1BPX9cwscWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWpNdXN0ZXJtYW5u2BhYZKRoZGlnZXN0SUQBZnJhbmRvbVggtAqtlqT4Iu6RfOQvf2x2x1jlMIYkT2nRlZEEMg5nfHxxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVlRXJpa2FqaXNzdWVyQXV0aIRDoQEmoRghWQF5MIIBdTCCARugAwIBAgIUUBL28YdIbv2G5xhoYEWg2KEOjl8wCgYIKoZIzj0EAwIwITESMBAGA1UEAwwJVGVzdCBJQUNBMQswCQYDVQQGDAJVUzAeFw0yNjA0MjQxMjIyMzlaFw0zNjA0MjIxMjIyMzlaMB8xEDAOBgNVBAMMB1Rlc3QgRFMxCzAJBgNVBAYMAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeuFGz2yEAalgMGVf5TvsYkvmmKD15YuZW6_jYXG263TlT5hfTFPjQgBuG8dqONudLYVg708obZHlef5_co5IaaMzMDEwHwYDVR0jBBgwFoAUr5xotg65uQhEFbtB9B3fIYgW870wDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIQDGeSXhehL3f4oweAVlOLZ0xhtXtqxWz9pn9TUnb3UuYwIgHYhePfvZ8VpPp7tt47orQfnDURorPldTMGk6o-0-r1FZAaTYGFkBn6ZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMaIAWCCtgK8YTscJ-FT2YUAMdSrCuv-dKL-howU8RGl7v1NgpwFYIKC-qen-xzWSxcVU9S6UlYC7Hm4pbvYMwwVtYAkqOjpEbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggr9ZPMS4MNgZ8bnvqL-WAnBgTaZDn7Cawr5YCKU8nKmwiWCDG2BFgilxkYLaKEKcIDN2iBopE2jbCB4JoJFaZQecLQmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWxpZGl0eUluZm-kZnNpZ25lZMB0MjAyNi0wNC0yNVQxMjoyMjozOVppdmFsaWRGcm9twHQyMDI2LTA0LTI1VDEyOjIyOjM5Wmp2YWxpZFVudGlswHQyMDM2LTA0LTIyVDEyOjIyOjM5Wm5leHBlY3RlZFVwZGF0ZcB0MjAyNy0wNC0yNVQxMjoyMjozOVpYQE-eLigm9MMwIxCsEBwZzM3tSuUDYbPvWh1evCDaVN87MSmQaE43BoHyyru10OE9KB0QA1yK5hhrOMljOnKnye1sZGV2aWNlU2lnbmVkompuYW1lU3BhY2Vz2BhBoGpkZXZpY2VBdXRooW9kZXZpY2VTaWduYXR1cmWEQ6EBJqD2WEBIwC3fhwbiZX4wQeGyH9yphwLfPLDBFkTx-xRLQCyJcQXDalz1uF1wjGFO3DiVJz7_Y6MtXjmn8o6mkGMho1eLZnN0YXR1cwA";
pub const SAMPLE_IACA_CERT_1: &str = "-----BEGIN CERTIFICATE-----
MIIBqDCCAU2gAwIBAgIUZdW2jOzOpHSw5Hgri+TO2r6GC4wwCgYIKoZIzj0EAwIw
ITESMBAGA1UEAwwJVGVzdCBJQUNBMQswCQYDVQQGDAJVUzAeFw0yNjA0MjQxMjIy
MzlaFw0zNjA0MjIxMjIyMzlaMCExEjAQBgNVBAMMCVRlc3QgSUFDQTELMAkGA1UE
BgwCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQdVSTSVssFILOLtJsNI4RO
mgfqPSflGt+uQlTrsGrPKjmrmxB5C+m0AANA2qY+9LuS5K4pR7HBQuOzkbagNtJd
o2MwYTAfBgNVHSMEGDAWgBSvnGi2Drm5CEQVu0H0Hd8hiBbzvTAOBgNVHQ8BAf8E
BAMCAQYwHQYDVR0OBBYEFK+caLYOubkIRBW7QfQd3yGIFvO9MA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAJicf0ZuX9+haK71Fn7nsHvVqmy225Tr
9yhyjeK+0Vq4AiEAuarnKhUf+DhuoYtr2+uwdzDseGh6h6AYH6zjnXhHg0w=
-----END CERTIFICATE-----";
pub const SAMPLE_IACA_CERT_2: &str = "-----BEGIN CERTIFICATE-----
MIIDlTCCAxygAwIBAgITZ1Q7u+8TXCBKFn6jmzvPwCx3bDAKBggqhkjOPQQDAzBb
MQswCQYDVQQGEwJYRzETMBEGA1UEChMKR29vZ2xlIExMQzEPMA0GA1UECxMGV2Fs
bGV0MSYwJAYDVQQDEx1JZGVudGl0eSBDcmVkZW50aWFsIFJvb3QgSUFDQTAeFw0y
NTAzMDQyMDUyMThaFw0zNTAzMDUwNjMyMTlaMFsxCzAJBgNVBAYTAlhHMRMwEQYD
VQQKEwpHb29nbGUgTExDMQ8wDQYDVQQLEwZXYWxsZXQxJjAkBgNVBAMTHUlkZW50
aXR5IENyZWRlbnRpYWwgUm9vdCBJQUNBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE
10PwkmBoPbxLLzP2Uph7NU55nM130T+wp8/QMdPa/SKXzMBTHINFb/uh0LmvKnfg
k4wiDhREGM9ty/yuLB/ZT+2abS6cD7FDyvhVBzwNNR0VVsCDdqv2Ob8KaQzLAXLn
o4IBoDCCAZwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
VR0OBBYEFBpEaI07wxCy/QSQd9UO5UBlzxTpMB8GA1UdIwQYMBaAFBpEaI07wxCy
/QSQd9UO5UBlzxTpMIGNBggrBgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBodHRw
Oi8vcHJpdmF0ZWNhLWNvbnRlbnQtNjdmNWY0MzItMDAwMC0yOTJmLTkxZDYtYWMz
ZWIxNGU3YjY4LnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vYWE3NjAzMGUwYjIyYTNh
OTVhOGIvY2EuY3J0MIGCBgNVHR8EezB5MHegdaBzhnFodHRwOi8vcHJpdmF0ZWNh
LWNvbnRlbnQtNjdmNWY0MzItMDAwMC0yOTJmLTkxZDYtYWMzZWIxNGU3YjY4LnN0
b3JhZ2UuZ29vZ2xlYXBpcy5jb20vYWE3NjAzMGUwYjIyYTNhOTVhOGIvY3JsLmNy
bDAhBgNVHRIEGjAYhhZodHRwczovL3d3dy5nb29nbGUuY29tMAoGCCqGSM49BAMD
A2cAMGQCMEleAuFo8yKVGk70NwJ/CzBt08mNHqBsxILZnTHwKvxXRkgDcXbwd931
bVvQoTYppQIwTCcq+Kic8KAe1Y2lu0ohvkxwST1s34ytFqJcElPddS76rX4rJLLW
wSde7pYC3LmY
-----END CERTIFICATE-----";
