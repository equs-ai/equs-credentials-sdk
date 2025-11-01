use agent_sdk::nonce;
use agent_sdk::nonce::{Nonce, NonceHandler};
use agent_sdk::vc::claims::{Claim, Claims};
use agent_sdk::vc::dcql::{DCQL, DCQLCredential};
use agent_sdk::vc::presentation_exchange::PresentationDefinition;
use agent_sdk::vc::{JsonLdAPIVCMetadata, VCMetadata};
use async_trait::async_trait;
use openid4vp::core::input_descriptor::InputDescriptor;
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
    pub vc_type: &'static str,
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
            time::Duration::days(5 * 365),
        )
        .unwrap(),
    ));

    let credential = Oid4VpTestCredential {
        format,
        vc_type: "PermanentResident",
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
        lifetime: time::Duration::days(365),
        disclosures: vec![
            "$.name".to_owned(),
            "$.surname".to_owned(),
            "$.address".to_owned(),
        ],
        credential_status: None,
    });

    let credential = Oid4VpTestCredential {
        format,
        vc_type: "https://credentials.example.com/identity_credential",
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
        lifetime: time::Duration::days(365),
        disclosures: vec![
            "$.name".to_owned(),
            "$.surname".to_owned(),
            "$.address".to_owned(),
        ],
        credential_status: None,
    });

    let credential = Oid4VpTestCredential {
        format,
        vc_type: "https://credentials.example.com/degree_credential",
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
