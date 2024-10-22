use agent_sdk::vc::presentation_exchange::PresentationDefinition;
use oid4vp::core::input_descriptor::InputDescriptor;
use serde_json::{json, Value as Json, Value};

pub type ValidateClaimsFunc = dyn Fn(Json) + Send + Sync;

pub struct Oid4VpTestCredential {
    pub id: &'static str,
    pub vct: &'static str,
    pub claims: Value,
}

pub struct Oid4VpTestCase {
    pub credentials: Vec<Oid4VpTestCredential>,
    pub presentation_definition: PresentationDefinition,
    pub validate: Box<ValidateClaimsFunc>,
}

pub const VERIFIER_URL: &str = "http://example.com";

fn sample_identity_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let credential = Oid4VpTestCredential {
        id: "Identity-1",
        vct: "https://credentials.example.com/identity_credential",
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

fn sample_degree_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let credential = Oid4VpTestCredential {
        id: "Degree-1",
        vct: "https://credentials.example.com/degree_credential",
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

pub fn single_presentation_case() -> Oid4VpTestCase {
    let (credential, descriptor) = sample_identity_credential();

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

pub fn multiple_presentation_case() -> Oid4VpTestCase {
    let (cred_identity, descriptor_identity) = sample_identity_credential();
    let (cred_degree, descriptor_degree) = sample_degree_credential();

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
