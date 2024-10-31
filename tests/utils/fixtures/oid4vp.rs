use agent_sdk::vc::presentation_exchange::PresentationDefinition;
use agent_sdk::vc::{JsonLdAPIVCMetadata, VCMetadata};
use oid4vp::core::input_descriptor::InputDescriptor;
use serde_json::{json, Value as Json, Value};

pub type ValidateClaimsFunc = dyn Fn(Json) + Send + Sync;

pub enum Oid4VpTestCredentialFormat {
    SdJwt(VCMetadata),
    LdpVc(JsonLdAPIVCMetadata),
}
pub struct Oid4VpTestCredential {
    pub format: Oid4VpTestCredentialFormat,
    pub vc_type: &'static str,
    pub claims: Value,
}

pub struct Oid4VpTestCase {
    pub credentials: Vec<Oid4VpTestCredential>,
    pub presentation_definition: PresentationDefinition,
    pub validate: Box<ValidateClaimsFunc>,
}

pub const VERIFIER_URL: &str = "http://example.com";

fn sample_jsonld_resident_card_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let format = Oid4VpTestCredentialFormat::LdpVc(JsonLdAPIVCMetadata::new(
        vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://w3id.org/citizenship/v1".to_string(),
        ],
        vec![
            "VerifiableCredential".to_string(),
            "PermanentResidentCard".to_string(),
        ],
    ));

    let credential = Oid4VpTestCredential {
        format,
        vc_type: "PermanentResidentCard",
        claims: json!({
            "type": ["PermanentResident", "Person"],
            "givenName": "John",
            "familyName": "Doe",
            "birthDate": "09/09/1989",
        }),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "resident-card",
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
                                "const": "PermanentResidentCard"
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

fn sample_sdjwt_identity_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let format = Oid4VpTestCredentialFormat::SdJwt(VCMetadata {
        vct: "https://credentials.example.com/identity_credential".to_owned(),
        lifetime: time::Duration::days(365),
        disclosures: vec![
            "$.name".to_owned(),
            "$.surname".to_owned(),
            "$.address".to_owned(),
        ],
    });

    let credential = Oid4VpTestCredential {
        format,
        vc_type: "https://credentials.example.com/identity_credential",
        claims: json!({
            "name": "John",
            "surname": "Doe",
            "address": "221B Baker Street",
            "date": "09/09/1989",
        }),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "Identity-1",
            "name": "Identity VC",
            "purpose": "We want an identity",
            "format": {
                "vc+sd-jwt": {
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
        }),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "Degree-1",
            "name": "Degree VC",
            "format": {
                "vc+sd-jwt": {
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

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor,
    );

    let validate: Box<ValidateClaimsFunc> = Box::new(|claims| {
        assert_eq!(
            claims["resident-card"]["credentialSubject"]["givenName"],
            json!("John")
        );
        assert_eq!(
            claims["resident-card"]["credentialSubject"]["familyName"],
            json!("Doe")
        );
        assert_eq!(
            claims["resident-card"]["credentialSubject"]["birthDate"],
            json!("09/09/1989")
        );
    });

    Oid4VpTestCase {
        credentials: vec![credential],
        presentation_definition,
        validate,
    }
}

pub fn single_sdjwt_presentation_case() -> Oid4VpTestCase {
    let (credential, descriptor) = sample_sdjwt_identity_credential();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor,
    );

    let validate: Box<ValidateClaimsFunc> = Box::new(|claims| {
        assert_eq!(
            claims["Identity-1"]["vct"],
            json!("https://credentials.example.com/identity_credential")
        );
        assert_eq!(claims["Identity-1"]["name"], json!("John"));
    });

    Oid4VpTestCase {
        credentials: vec![credential],
        presentation_definition,
        validate,
    }
}

pub fn multiple_sdjwt_presentation_case() -> Oid4VpTestCase {
    let (cred_identity, descriptor_identity) = sample_sdjwt_identity_credential();
    let (cred_degree, descriptor_degree) = sample_sdjwt_degree_credential();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor_identity,
    )
    .add_input_descriptors(descriptor_degree);

    let validate: Box<ValidateClaimsFunc> = Box::new(|claims| {
        assert_eq!(
            claims["Identity-1"]["vct"],
            json!("https://credentials.example.com/identity_credential")
        );
        assert_eq!(claims["Identity-1"]["name"], json!("John"));
        assert_eq!(
            claims["Degree-1"]["vct"],
            json!("https://credentials.example.com/degree_credential")
        );
        assert_eq!(
            claims["Degree-1"]["degree"]["type"],
            json!("BachelorDegree")
        );
    });

    Oid4VpTestCase {
        credentials: vec![cred_identity, cred_degree],
        presentation_definition,
        validate,
    }
}
