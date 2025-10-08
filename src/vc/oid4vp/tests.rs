pub mod fixtures {
    pub const VERIFIER_URL: &str = "http://127.0.0.1:55796";
    pub const NONCE: &str = "n0NcE";
    pub const CLIENT_ID: &str = "wallet-dev";
    pub const STATE: &str = "1d8b0d93-86e8-4135-87d4-524bb0500bf3";
    pub const REQUEST_URI: &str = "openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3AzDnaebMD6CqPmJL8WxF6YffAAbbK935aaKbyVEyuGQtukXk6f&request_uri=http%3A%2F%2F127.0.0.1%3A55796%2Frequest";
    pub const CREDENTIAL_ID: &str = "abcde";

    pub mod single_presentation {
        pub mod json_ld {
            use crate::vc::ClaimFormatDesignation;
            use crate::vc::claims::Claims;
            use crate::vc::oid4vp::ResolvedAuthRequest;
            use crate::vc::oid4vp::tests::utils::PresentationTestCase;
            use crate::vc::presentation_exchange::PresentationSubmission;
            use serde_json::json;

            const PRESENTATION_SUBMISSION: &str = r#"{
                "id": "00000000-0000-0000-0000-000000000000",
                "definition_id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                "descriptor_map": [
                    {
                        "id": "Identity-1",
                        "format": "ldp_vc",
                        "path": "$"
                    }
                ]
            }"#;

            const PRESENTATION_DEFINITION_FORMAT: &str = r#"{
              "ldp_vc": {
                "proof_type": ["EcdsaRdfc2019", "EdDsaRdfc2022"]
              }
            }"#;

            pub const AUTH_REQUEST: &str = r#"
                {
                  "client_id": "decentralized_identifier:did:key:zDnaehgaHKAP7LAA3Kwa4FjXjJ1G3BcaHqr5gfRySJcGDgBtV",
                  "state": null,
                  "presentation_definition": {
                    "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                    "input_descriptors": [
                      {
                        "id": "Identity-1",
                        "constraints": {
                          "fields": [
                            {
                              "path": [
                                "$.credentialSubject.name.givenName",
                                "$.credentialSubject.name.familyName"
                              ]
                            },
                            {
                              "path": [
                                "$.type"
                              ],
                              "filter": {
                                "type": "array",
                                "contains": {
                                    "const": "VerifiableCredential"
                                }
                              }
                            },
                            {
                                "path": ["$.issuer"]
                            }
                          ]
                        },
                        "name": "Identity VC",
                        "purpose": "We want an identity",
                         "format": {
                            "ldp_vc": {
                                "proof_type": [
                                    "EcdsaRdfc2019",
                                    "EdDsaRdfc2022"
                               ]
                            }
                        }
                      }
                    ],
                    "name": "Example with selective disclosure"
                  },
                  "nonce": "3DaLwdi89qDgplpSwAspX6wWzm6pLkzaN3Xuk-ar5zY",
                  "response_mode": "direct_post",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                  "client_metadata": {
                    "vp_formats_supported": {
                        "dc+sd-jwt": {
                            "sd-jwt_alg_values": ["EdDSA", "ES256"],
                            "kb-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    }
                  }
                }
            "#;

            pub fn presentation_submission() -> PresentationSubmission {
                serde_json::from_str(PRESENTATION_SUBMISSION).unwrap()
            }

            pub fn auth_request() -> ResolvedAuthRequest {
                serde_json::from_str(AUTH_REQUEST).unwrap()
            }

            pub fn credential_1() -> Claims {
                json!({
                    "type": vec![
                        "VerifiableCredential".to_string(),
                        "AlumniCredential".to_string(),
                    ],
                    "name": {
                        "givenName": "John",
                        "familyName": "Jones"
                    }
                })
                .try_into()
                .unwrap()
            }

            pub fn credential_2() -> Claims {
                json!({
                    "type": vec![
                        "VerifiableCredential".to_string(),
                        "AlumniCredential2".to_string(),
                    ],
                    "name": "Mike",
                    "degree": "Bachelors"
                })
                .try_into()
                .unwrap()
            }

            pub fn credential_3() -> Claims {
                json!({
                    "type": vec![
                        "VerifiableCredential".to_string(),
                        "UniversityDegreeCredential".to_string(),
                    ],
                    "name": "Alex",
                    "degree": "Masters",
                    "college": "Oxford University"
                })
                .try_into()
                .unwrap()
            }

            pub fn credential_4() -> Claims {
                json!({
                    "type": vec![
                        "VerifiableCredential".to_string(),
                        "UniversityDegreeCredential2".to_string(),
                    ],
                    "name": "Mark",
                    "degree": "Bachelors",
                })
                .try_into()
                .unwrap()
            }

            pub fn presentation_test_case() -> PresentationTestCase {
                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request(),
                    credential_data: vec![credential_1()],
                    presentation_submission: presentation_submission(),
                    response_metadata: Default::default(),
                    expected_credential_data: vec![credential_1()],
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_filter_by_path() -> PresentationTestCase {
                let credential_data: Vec<Claims> =
                    vec![credential_1(), credential_2(), credential_3()];

                let constraints = r#"
                {
                  "fields": [
                    {
                      "path": [
                        "$.credentialSubject.college"
                      ]
                    }
                  ]
                }
                "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    presentation_submission,
                    response_metadata: Default::default(),
                    expected_credential_data: vec![credential_3()],
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_filter_by_cred_type() -> PresentationTestCase {
                let credential_data: Vec<Claims> =
                    vec![credential_1(), credential_2(), credential_3()];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.type"
                          ],
                          "filter": {
                            "type": "array",
                            "contains": {
                                "const": "AlumniCredential"
                            }
                          }
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_1()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_filter_by_cred_type_and_email()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.type"
                          ],
                          "filter": {
                            "type": "array",
                            "contains": {
                                "const": "UniversityDegreeCredential2"
                            }
                          }
                        },
                        {
                          "path": [
                            "$.credentialSubject.degree"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "Bachelors"
                          }
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_4()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_optional_field() -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.type"
                          ],
                          "filter": {
                            "type": "array",
                            "contains": {
                                "const": "AlumniCredential"
                            }
                          }
                        },
                        {
                          "path": [
                            "$.credentialSubject.degree"
                          ],
                          "optional": true
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_1()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_constraints_for_particular_fields()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.credentialSubject.name"
                          ]
                        },
                        {
                          "path": [
                            "$.type",
                            "$.credentialSubject.degree"
                          ]
                        },
                        {
                          "path": [
                            "$.credentialSubject.college"
                          ],
                          "optional": false
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_3()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_constraints_with_patterns() -> PresentationTestCase {
                let cred: Claims = json!({
                    "type": vec![
                        "VerifiableCredential".to_string(),
                        "AlumniCredential".to_string(),
                    ],
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                    "address": {
                        "country": "UK",
                        "city": "London"
                    },
                    "birthDate": "1980-01-01",
                    "graduationYear": 2020

                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred.clone()];
                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.credentialSubject.fakEmail",
                            "$.credentialSubject.email",
                            "$.credentialSubject.fakEmail2"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^[\\w\\.-]+@[a-zA-Z\\d\\.-]+\\.[a-zA-Z]{2,}$"
                          }
                        },
                        {
                          "path": [
                            "$.credentialSubject.address.not.exist.start",
                            "$.credentialSubject.address.country",
                            "$.credentialSubject.address.not.exist.middle",
                            "$.credentialSubject.address.city",
                            "$.credentialSubject.address.not.exist.end"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^\\p{L}+$"
                          }
                        },
                        {
                          "path": [
                            "$.credentialSubject.position"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "lead engineer"
                          },
                          "optional": false
                        },
                        {
                          "path": [
                            "$.credentialSubject.birthDate"
                          ],
                          "filter": {
                            "pattern": "^(?P<year>\\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$"
                          },
                          "optional": false
                        },
                        {
                          "path": [
                            "$.credentialSubject.graduationYear"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^\\d{4}$"
                          },
                          "optional": true
                        },
                        {
                          "path": [
                            "$.credentialSubject.status"
                          ],
                          "optional": true
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
            pub fn presentation_test_case_with_constraints_with_invalid_value_for_pattern()
            -> PresentationTestCase {
                let cred: Claims = json!({
                    "type": vec![
                        "VerifiableCredential".to_string(),
                        "AlumniCredential".to_string(),
                    ],
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                    "address": {
                        "country": "UK",
                        "city": "London"
                    },
                    "birthDate": "1980:01:01",
                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred.clone()];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.fake.field",
                            "$.credentialSubject.email",
                            "$.fake.field2"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^[\\w\\.-]+@[a-zA-Z\\d\\.-]+\\.[a-zA-Z]{2,}$"
                          }
                        },
                        {
                          "path": [
                            "$.credentialSubject.fakeDate",
                            "$.credentialSubject.birthDate",
                            "$.credentialSubject.fakeBirthDate"
                          ],
                          "filter": {
                            "pattern": "^(?P<year>\\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$"
                          },
                          "optional": false
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
            pub fn presentation_test_case_with_constraints_with_invalid_value_for_const()
            -> PresentationTestCase {
                let cred: Claims = json!({
                    "type": vec![
                        "VerifiableCredential".to_string(),
                        "AlumniCredential".to_string(),
                    ],
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "Senior developer"

                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred.clone()];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.credentialSubject.email"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^[\\w\\.-]+@[a-zA-Z\\d\\.-]+\\.[a-zA-Z]{2,}$"
                          }
                        },
                        {
                          "path": [
                            "$.credentialSubject.position"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "lead engineer"
                          }
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
            pub fn presentation_test_case_with_constraints_with_absent_required_claim()
            -> PresentationTestCase {
                let cred: Claims = json!({
                    "type": vec![
                        "VerifiableCredential".to_string(),
                        "AlumniCredential2".to_string(),
                    ],
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred.clone()];

                let constraints = r#"
                    {
                      "fields": [
                      {
                          "path": [
                            "$.credentialSubject.email"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^[\\w\\.-]+@[a-zA-Z\\d\\.-]+\\.[a-zA-Z]{2,}$"
                          }
                        },
                        {
                          "path": [
                            "$.credentialSubject.status"
                          ],
                          "optional": false
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn dcql_test_case_with_type_only() -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "ldp_vc",
                                        "meta": {
                                            "type_values": [
                                              [
                                                  "https://www.w3.org/2018/credentials#VerifiableCredential",
                                                  "https://example.org/examples#AlumniCredential",
                                                  "https://example.org/examples#BachelorDegree"
                                              ],
                                              [
                                                  "https://www.w3.org/2018/credentials#VerifiableCredential",
                                                  "https://example.org/examples#UniversityDegreeCredential"
                                              ],
                                              [
                                                  "IdentityCredential"
                                              ]
                                            ]
                                        }
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_3()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn dcql_test_case_with_claim_sets() -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "ldp_vc",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "id": "1",
                                                "path": ["credentialSubject", "name"]
                                            },
                                            {
                                                "id": "2",
                                                "path": ["credentialSubject", "degree"]
                                            },
                                            {
                                                "id": "3",
                                                "path": ["credentialSubject", "college"]
                                            }
                                        ],
                                        "claim_sets": [["1", "2"], ["3", "4"]]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_3()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn dcql_test_case_without_claim_sets() -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "ldp_vc",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "id": "1",
                                                "path": ["credentialSubject", "name"]
                                            },
                                            {
                                                "id": "2",
                                                "path": ["credentialSubject", "degree"]
                                            },
                                            {
                                                "id": "3",
                                                "path": ["credentialSubject", "college"]
                                            }
                                        ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_3()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn dcql_test_case_with_multiple_credentials() -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "ldp_vc",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "path": ["credentialSubject", "name", "givenName"]
                                            },
                                            {
                                                "path": ["credentialSubject", "name", "familyName"]
                                            }
                                        ]
                                    },
                                    {
                                        "id": "pid2",
                                        "format": "ldp_vc",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "path": ["credentialSubject", "name"]
                                            },
                                            {
                                                "path": ["credentialSubject", "degree"]
                                            },
                                            {
                                                "path": ["credentialSubject", "college"]
                                            }
                                        ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::LdpVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_1(), credential_3()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
        }

        pub mod sd_jwt {
            use crate::nonce::Nonce;
            use crate::vc::claims::Claims;
            use crate::vc::oid4vp::tests::fixtures::NONCE;
            use crate::vc::oid4vp::tests::fixtures::multi_presentation::transaction_data;
            use crate::vc::oid4vp::tests::utils::{PresentationTestCase, VerificationTestCase};
            use crate::vc::oid4vp::{
                ClientMetadata, PresentationSession, ResolvedAuthRequest, ResolvedPresentationQuery,
            };
            use crate::vc::presentation_exchange::{
                PresentationDefinition, PresentationSubmission,
            };
            use openid4vp::core::credential_format::ClaimFormatDesignation;
            use serde_json::json;

            const PRESENTATION_DEFINITION_FORMAT: &str = r#"{
              "dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256", "EdDSA"],
                "kb-jwt_alg_values": ["ES256", "EdDSA"]
              }
            }"#;

            const PRESENTATION_DEFINITION: &str = r#"{
               "id":"327ad171-c80a-485b-b098-50d7ad278ef6",
               "input_descriptors":[
                  {
                     "id":"Identity-1",
                     "name":"Identity VC",
                     "purpose":"We want an identity",
                     "format":{
                        "dc+sd-jwt":{
                            "sd-jwt_alg_values": ["ES256", "EdDSA"],
                            "kb-jwt_alg_values": ["ES256", "EdDSA"]
                        }
                     },
                     "constraints":{
                        "fields":[
                           {
                              "path":[
                                 "$.vct"
                              ],
                              "filter":{
                                 "type":"string",
                                 "const":"https://credentials.example.com/identity_credential"
                              }
                           },
                           {
                              "path":[
                                 "$.name"
                              ]
                           }
                        ]
                     }
                  }
               ]
            }"#;

            const PRESENTATION_SUBMISSION: &str = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "definition_id": "327ad171-c80a-485b-b098-50d7ad278ef6",
            "descriptor_map": [
                {
                    "id": "Identity-1",
                    "format": "dc+sd-jwt",
                    "path": "$"
                }
            ]
        }"#;

            pub const AUTH_REQUEST_JWT: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWViTUQ2Q3FQbUpMOFd4RjZZZmZBQWJiSzkzNWFhS2J5VkV5dUdRdHVrWGs2ZiN6RG5hZWJNRDZDcVBtSkw4V3hGNllmZkFBYmJLOTM1YWFLYnlWRXl1R1F0dWtYazZmIiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6IjFkOGIwZDkzLTg2ZTgtNDEzNS04N2Q0LTUyNGJiMDUwMGJmMyIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiMlQwbjJxZ2RYNlh5RXotVWdDSEZNSDZmUmw5LXM0SURXcmtubmtHVzBWMCIsImNsaWVudF9tZXRhZGF0YSI6eyJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRWREU0EiLCJFUzI1NiJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFZERTQSIsIkVTMjU2Il19fSwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJlbmMiLCJhbGciOiJFUzI1NiIsImtpZCI6IlJTZE5GZG5HSG06UDI1NjoiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkxiLTNrcG9tZS1nbHZTQXJaV0RPUlVva3JseWw5VFZ2M2h6bVV1QmdUWE0iLCJ5IjoidjFGZ2NPVHhNMTd0OWZ3dVFSeEo3S1JFcERYSEZTejRrZzJVQ2VDbVhidyJ9XX0sImVuY3J5cHRlZF9yZXNwb25zZV9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4R0NNIiwiQTEyOENCQy1IUzI1NiJdLCJzdWJqZWN0X3N5bnRheF90eXBlc19zdXBwb3J0ZWQiOlsiZGlkOmtleSJdfSwiY2xpZW50X2lkIjoiZGVjZW50cmFsaXplZF9pZGVudGlmaWVyOmRpZDprZXk6ekRuYWViTUQ2Q3FQbUpMOFd4RjZZZmZBQWJiSzkzNWFhS2J5VkV5dUdRdHVrWGs2ZiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzI3YWQxNzEtYzgwYS00ODViLWIwOTgtNTBkN2FkMjc4ZWY2IiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIn0sInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm5hbWUiXSwib3B0aW9uYWwiOnRydWUsInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX0sIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7ImRjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl0sImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXX19fV19LCJyZXNwb25zZV91cmkiOiJodHRwOi8vMTI3LjAuMC4xOjU1Nzk2L2F1dGgifQ.vx7zZECHmm-hJ6Gnt0FAQf4aCCrYpbyoIQHJOUcTOw6cESozijzV8Y2VKmoEHefiEM6RWYYs7IZcF4hLZ2fdyw";
            pub const AUTH_REQUEST: &str = r#"
            {
              "response_type": "vp_token",
              "state": "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
              "response_mode": "direct_post",
              "nonce": "2T0n2qgdX6XyEz-UgCHFMH6fRl9-s4IDWrknnkGW0V0",
              "client_metadata": {
                "vp_formats_supported": {
                  "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["EdDSA", "ES256"],
                    "kb-jwt_alg_values": ["EdDSA", "ES256"]
                  }
                },
                "jwks": {
                  "keys": [
                    {
                      "use": "enc",
                      "alg": "ES256",
                      "kid": "RSdNFdnGHm:P256:",
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "Lb-3kpome-glvSArZWDORUokrlyl9TVv3hzmUuBgTXM",
                      "y": "v1FgcOTxM17t9fwuQRxJ7KREpDXHFSz4kg2UCeCmXbw"
                    }
                  ]
                },
                "encrypted_response_enc_values_supported": [
                  "A128GCM",
                  "A128CBC-HS256"
                ],
                "subject_syntax_types_supported": [
                  "did:key"
                ]
              },
              "client_id": "decentralized_identifier:did:key:zDnaebMD6CqPmJL8WxF6YffAAbbK935aaKbyVEyuGQtukXk6f",
              "presentation_definition": {
                "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                "input_descriptors": [
                  {
                    "id": "Identity-1",
                    "constraints": {
                      "fields": [
                        {
                          "path": [
                            "$.vct"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/identity_credential"
                          },
                          "predicate": null,
                          "intent_to_retain": false
                        },
                        {
                          "path": [
                            "$.name"
                          ],
                          "optional": true,
                          "predicate": null,
                          "intent_to_retain": false
                        }
                      ]
                    },
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
                    }
                  }
                ]
              },
              "response_uri": "http://127.0.0.1:55796/auth"
            }"#;
            pub const AUTH_REQUEST_WITH_WRONG_CLIENT_ID: &str = r#"
                {
                  "client_id": "decentralized_identifier:did:key:1",
                  "state": null,
                  "presentation_definition": {
                    "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                    "input_descriptors": [
                      {
                        "id": "Identity-1",
                        "constraints": {
                          "fields": [
                            {
                              "path": [
                                "$.name"
                              ],
                              "predicate": null,
                              "optional": true,
                              "intent_to_retain": false
                            },
                            {
                              "path": [
                                "$.vct"
                              ],
                              "predicate": null,
                              "filter": {
                                "type": "string",
                                "const": "https://credentials.example.com/identity_credential"
                              },
                              "intent_to_retain": false
                            }
                          ]
                        },
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
                        }
                      }
                    ],
                    "name": "Example with selective disclosure"
                  },
                  "nonce": "3DaLwdi89qDgplpSwAspX6wWzm6pLkzaN3Xuk-ar5zY",
                  "response_mode": "direct_post",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                  "client_metadata": {
                    "vp_formats_supported": {
                        "dc+sd-jwt": {
                            "sd-jwt_alg_values": ["EdDSA", "ES256"],
                            "kb-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    }
                  }
                }"#;

            pub const AUTH_REQUEST_WITH_UNSUPPORTED_CLIENT_ID_PREFIX: &str = r#"
                {
                  "client_id": "origin:some-link",
                  "state": null,
                  "presentation_definition": {
                    "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                    "input_descriptors": [
                      {
                        "id": "Identity-1",
                        "constraints": {
                          "fields": [
                            {
                              "path": [
                                "$.name"
                              ],
                              "predicate": null,
                              "optional": true,
                              "intent_to_retain": false
                            },
                            {
                              "path": [
                                "$.vct"
                              ],
                              "predicate": null,
                              "filter": {
                                "type": "string",
                                "const": "https://credentials.example.com/identity_credential"
                              },
                              "intent_to_retain": false
                            }
                          ]
                        },
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
                        }
                      }
                    ],
                    "name": "Example with selective disclosure"
                  },
                  "nonce": "3DaLwdi89qDgplpSwAspX6wWzm6pLkzaN3Xuk-ar5zY",
                  "response_mode": "direct_post",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                  "client_metadata": {
                    "vp_formats_supported": {
                       "dc+sd-jwt": {
                            "sd-jwt_alg_values": ["EdDSA", "ES256"],
                            "kb-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    }
                  }
                }"#;

            pub const AUTH_REQUEST_WITH_DIRECT_POST_JWT_RESPONSE: &str = r#"
                {
                  "client_id": "decentralized_identifier:did:key:zDnaehgaHKAP7LAA3Kwa4FjXjJ1G3BcaHqr5gfRySJcGDgBtV",
                  "state": null,
                  "presentation_definition": {
                    "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                    "input_descriptors": [
                      {
                        "id": "Identity-1",
                        "constraints": {
                          "fields": [
                            {
                              "path": [
                                "$.name"
                              ],
                              "predicate": null,
                              "optional": true,
                              "intent_to_retain": false
                            },
                            {
                              "path": [
                                "$.vct"
                              ],
                              "predicate": null,
                              "filter": {
                                "type": "string",
                                "const": "https://credentials.example.com/identity_credential"
                              },
                              "intent_to_retain": false
                            }
                          ]
                        },
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
                        }
                      }
                    ],
                    "name": "Example with selective disclosure"
                  },
                  "nonce": "3DaLwdi89qDgplpSwAspX6wWzm6pLkzaN3Xuk-ar5zY",
                  "response_mode": "direct_post.jwt",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                  "client_metadata": {
                    "vp_formats_supported": {
                        "dc+sd-jwt": {
                            "sd-jwt_alg_values": ["EdDSA", "ES256"],
                            "kb-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    },
                    "jwks": {
                      "keys": [
                        {
                          "kty":"EC", "kid":"ac", "use":"enc", "crv":"P-256","alg":"ES256",
                          "x": "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
                          "y": "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY"
                        }
                     ]
                    },
                    "encrypted_response_enc_values_supported": ["A128GCM", "A128CBC-HS256"]
                  }
                }"#;
            pub const AUTH_REQUEST_WITH_NON_URL_CLIENT_ID_PREFIX: &str = r#"
                {
                  "client_id": "redirect_uri:non-link-id",
                  "state": null,
                  "presentation_definition": {
                    "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                    "input_descriptors": [
                      {
                        "id": "Identity-1",
                        "constraints": {
                          "fields": [
                            {
                              "path": [
                                "$.name"
                              ],
                              "predicate": null,
                              "optional": true,
                              "intent_to_retain": false
                            },
                            {
                              "path": [
                                "$.vct"
                              ],
                              "predicate": null,
                              "filter": {
                                "type": "string",
                                "const": "https://credentials.example.com/identity_credential"
                              },
                              "intent_to_retain": false
                            }
                          ]
                        },
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
                        }
                      }
                    ],
                    "name": "Example with selective disclosure"
                  },
                  "nonce": "3DaLwdi89qDgplpSwAspX6wWzm6pLkzaN3Xuk-ar5zY",
                  "response_mode": "direct_post",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                  "client_metadata": {
                    "vp_formats_supported": {
                        "dc+sd-jwt": {
                            "sd-jwt_alg_values": ["EdDSA", "ES256"],
                            "kb-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    }
                  }
                }"#;

            pub const AUTH_REQUEST_WITH_REDIRECT_URI: &str = r#"
                {
                  "client_id": "redirect_uri:https://localhost:8080",
                  "state": null,
                  "presentation_definition": {
                    "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                    "input_descriptors": [
                      {
                        "id": "Identity-1",
                        "constraints": {
                          "fields": [
                            {
                              "path": [
                                "$.name"
                              ],
                              "predicate": null,
                              "optional": true,
                              "intent_to_retain": false
                            },
                            {
                              "path": [
                                "$.vct"
                              ],
                              "predicate": null,
                              "filter": {
                                "type": "string",
                                "const": "https://credentials.example.com/identity_credential"
                              },
                              "intent_to_retain": false
                            }
                          ]
                        },
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
                        }
                      }
                    ],
                    "name": "Example with selective disclosure"
                  },
                  "nonce": "3DaLwdi89qDgplpSwAspX6wWzm6pLkzaN3Xuk-ar5zY",
                  "response_mode": "direct_post",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                  "client_metadata": {
                    "vp_formats_supported": {
                        "dc+sd-jwt": {
                            "sd-jwt_alg_values": ["EdDSA", "ES256"],
                            "kb-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    }
                  }
                }"#;
            pub const AUTH_REQUEST_WITH_STATE: &str = r#"
                {
                  "client_id": "decentralized_identifier:did:key:zDnaex9UKhcwNpfrPva1HLj6DECNHhHkmuY6xszv1KGWksvfL",
                  "state": "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
                  "presentation_definition": {
                    "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                    "input_descriptors": [
                      {
                        "id": "Identity-1",
                        "constraints": {
                          "fields": [
                            {
                              "path": [
                                "$.name"
                              ],
                              "predicate": null,
                              "optional": true,
                              "intent_to_retain": false
                            },
                            {
                              "path": [
                                "$.vct"
                              ],
                              "predicate": null,
                              "filter": {
                                "type": "string",
                                "const": "https://credentials.example.com/identity_credential"
                              },
                              "intent_to_retain": false
                            }
                          ]
                        },
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
                        }
                      }
                    ],
                    "name": "Example with selective disclosure"
                  },
                  "nonce": "XUcfTNfJ-d5pm99XUKG7mGKukwXeDasaRlghKEpGxh0",
                  "response_mode": "direct_post",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                "client_metadata": {
                "vp_formats_supported": {
                    "dc+sd-jwt": {
                        "sd-jwt_alg_values": ["EdDSA", "ES256"],
                        "kb-jwt_alg_values": ["EdDSA", "ES256"]
                    }
                }
              }}
            "#;

            pub const CLIENT_METADATA_NO_KEYS: &str = r#"
                {
                    "vp_formats_supported": {
                        "dc+sd-jwt": {
                            "sd-jwt_alg_values": ["EdDSA", "ES256"],
                            "kb-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    },
                    "jwks": {
                        "keys": [

                        ]
                    },
                    "encrypted_response_enc_values_supported": ["A128GCM", "A128CBC-HS256"]
                }
            "#;

            pub fn presentation_definition() -> ResolvedPresentationQuery {
                let pd: PresentationDefinition =
                    serde_json::from_str(PRESENTATION_DEFINITION).unwrap();
                ResolvedPresentationQuery::PresentationDefinition(pd)
            }

            pub fn presentation_submission() -> PresentationSubmission {
                serde_json::from_str(PRESENTATION_SUBMISSION).unwrap()
            }

            pub fn auth_request() -> ResolvedAuthRequest {
                serde_json::from_str(AUTH_REQUEST).unwrap()
            }
            pub fn auth_request_with_direct_post_jwt_response() -> ResolvedAuthRequest {
                serde_json::from_str(AUTH_REQUEST_WITH_DIRECT_POST_JWT_RESPONSE).unwrap()
            }

            pub fn auth_request_with_state() -> ResolvedAuthRequest {
                serde_json::from_str(AUTH_REQUEST_WITH_STATE).unwrap()
            }

            pub fn credential_1() -> Claims {
                json!({
                    "vct":"https://credentials.example.com/identity_credential",
                    "name": "Mark",
                })
                .try_into()
                .unwrap()
            }

            pub fn credential_2() -> Claims {
                json!({
                    "vct": "https://credentials.example.com/student_credential_1",
                    "name": "Mike",
                    "email": {
                        "university": "university@mike.com",
                        "personal": "personal@mike.com"
                    },
                    "address": {
                        "country": "UK",
                        "city": "London"
                    },
                    "age": 20
                })
                .try_into()
                .unwrap()
            }
            pub fn credential_3() -> Claims {
                json!({
                    "vct": "https://credentials.example.com/student_credential_2",
                    "name": "John",
                    "email": "john@example.com"
                })
                .try_into()
                .unwrap()
            }

            pub fn credential_4() -> Claims {
                json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "name": "Alex",
                    "email": "alex@example.com"
                })
                .try_into()
                .unwrap()
            }

            pub fn presentation_session() -> PresentationSession {
                PresentationSession {
                    nonce: Nonce::from_secret(NONCE.to_owned()),
                    resolved_presentation_query: presentation_definition(),
                    auth_request_jwt: Default::default(),
                }
            }

            pub fn presentation_test_case() -> PresentationTestCase {
                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request(),
                    credential_data: vec![credential_1()],
                    presentation_submission: presentation_submission(),
                    response_metadata: Default::default(),
                    expected_credential_data: vec![credential_1()],
                    transaction_data: Some(transaction_data()),
                }
            }

            pub fn presentation_test_case_with_direct_post_jwt() -> PresentationTestCase {
                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request_with_direct_post_jwt_response(),
                    credential_data: vec![credential_1()],
                    presentation_submission: presentation_submission(),
                    response_metadata: Default::default(),
                    expected_credential_data: vec![credential_1()],
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_filter_by_path() -> PresentationTestCase {
                let credential_data: Vec<Claims> =
                    vec![credential_1(), credential_2(), credential_3()];

                let constraints = r#"
                {
                  "fields": [
                    {
                      "path": [
                        "$.email.personal"
                      ]
                    }
                  ]
                }
                "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    presentation_submission,
                    response_metadata: Default::default(),
                    expected_credential_data: vec![credential_2()],
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_filter_by_cred_type() -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.vct"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/employee_credential"
                          }
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_4()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_filter_by_cred_type_and_email()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.vct"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/student_credential_2"
                          }
                        },
                        {
                          "path": [
                            "$.email"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "john@example.com"
                          }
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_3()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_optional_field() -> PresentationTestCase {
                let credential_data: Vec<Claims> =
                    vec![credential_2(), credential_3(), credential_4()];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.vct"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/student_credential_1"
                          }
                        },
                        {
                          "path": [
                            "$.age"
                          ],
                          "optional": true
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_2()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_constraints_for_particular_fields()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.email"
                          ]
                        },
                        {
                          "path": [
                            "$.vct",
                            "$.address.country",
                            "$.address.city"
                          ]
                        },
                        {
                          "path": [
                            "$.age"
                          ],
                          "optional": false
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_2()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
            pub fn presentation_test_case_with_constraints_with_patterns() -> PresentationTestCase {
                let cred: Claims = json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                    "address": {
                        "country": "UK",
                        "city": "London"
                    },
                    "birthDate": "1980-01-01",
                    "graduationYear": 2020

                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred.clone()];
                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.email"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^[\\w\\.-]+@[a-zA-Z\\d\\.-]+\\.[a-zA-Z]{2,}$"
                          }
                        },
                        {
                          "path": [
                            "$.address.country",
                            "$.address.city"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^\\p{L}+$"
                          }
                        },
                        {
                          "path": [
                            "$.position"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "lead engineer"
                          },
                          "optional": false
                        },
                        {
                          "path": [
                            "$.birthDate"
                          ],
                          "filter": {
                            "pattern": "^(?P<year>\\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$"
                          },
                          "optional": false
                        },
                        {
                          "path": [
                            "$.graduationYear"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^\\d{4}$"
                          },
                          "optional": true
                        },
                        {
                          "path": [
                            "$.status"
                          ],
                          "optional": true
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
            pub fn presentation_test_case_with_constraints_with_invalid_value_for_pattern()
            -> PresentationTestCase {
                let cred: Claims = json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                    "address": {
                        "country": "UK",
                        "city": "London"
                    },
                    "birthDate": "1980:01:01",
                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred.clone()];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.email"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^[\\w\\.-]+@[a-zA-Z\\d\\.-]+\\.[a-zA-Z]{2,}$"
                          }
                        },
                        {
                          "path": [
                            "$.birthDate"
                          ],
                          "filter": {
                            "pattern": "^(?P<year>\\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$"
                          },
                          "optional": false
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
            pub fn presentation_test_case_with_constraints_with_invalid_value_for_const()
            -> PresentationTestCase {
                let cred: Claims = json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "Senior developer"

                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred.clone()];

                let constraints = r#"
                    {
                      "fields": [
                        {
                          "path": [
                            "$.email"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^[\\w\\.-]+@[a-zA-Z\\d\\.-]+\\.[a-zA-Z]{2,}$"
                          }
                        },
                        {
                          "path": [
                            "$.position"
                          ],
                          "filter": {
                            "type": "string",
                            "const": "lead engineer"
                          }
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
            pub fn presentation_test_case_with_constraints_with_absent_required_claim()
            -> PresentationTestCase {
                let cred: Claims = json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred.clone()];

                let constraints = r#"
                    {
                      "fields": [
                      {
                          "path": [
                            "$.email"
                          ],
                          "filter": {
                            "type": "string",
                            "pattern": "^[\\w\\.-]+@[a-zA-Z\\d\\.-]+\\.[a-zA-Z]{2,}$"
                          }
                        },
                        {
                          "path": [
                            "$.status"
                          ],
                          "optional": false
                        }
                      ]
                    }
                    "#;
                let auth_request = PresentationTestCase::build_auth_request(
                    PRESENTATION_DEFINITION_FORMAT,
                    constraints,
                );
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_with_state() -> PresentationTestCase {
                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request_with_state(),
                    credential_data: vec![credential_1()],
                    presentation_submission: presentation_submission(),
                    response_metadata: Default::default(),
                    expected_credential_data: vec![credential_1()],
                    transaction_data: None,
                }
            }

            pub fn verification_test_case() -> VerificationTestCase {
                VerificationTestCase {
                    credential_data: vec![credential_1()],
                    presentation_submission: presentation_submission(),
                    session: presentation_session(),
                }
            }

            pub fn client_metadata_no_keys() -> ClientMetadata {
                serde_json::from_str(CLIENT_METADATA_NO_KEYS).unwrap()
            }
            pub fn presentation_test_case_for_dcql_with_vct_only() -> PresentationTestCase {
                let cred1: Claims = json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                })
                .try_into()
                .unwrap();
                let cred2: Claims = json!({
                    "vct": "some_vct",
                    "id": "John",
                    "username": "john@example.com",
                    "age": 35,
                    "occupation": "lead engineer",
                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred1.clone(), cred2.clone()];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {
                                            "vct_values": ["some_vct"]
                                        }
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![cred2],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_dcql_without_claim_sets_multiple_result()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "path": ["name"]
                                            }
                                        ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data: credential_data.clone(),
                    expected_credential_data: credential_data,
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_dcql_without_claim_sets_unique_result()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {
                                            "vct_values": ["https://credentials.example.com/employee_credential", "not-existing-vct"]
                                        },
                                        "claims": [
                                            {
                                                "path": ["name"]
                                            }
                                        ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_4()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_dcql_without_claim_sets_empty_result()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {
                                            "vct_values": ["https://credentials.example.com/employee_credential", "not-existing-vct"]
                                        },
                                        "claims": [
                                            {
                                                "path": ["name"]
                                            },
                                            {
                                                "path": ["email", "work"]
                                            }
                                        ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_dcql_with_claim_sets() -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "id": "first",
                                                "path": ["name"]
                                            },
                                            {
                                                "id": "second",
                                                "path": ["email", "work"]
                                            },
                                            {
                                                "id": "third",
                                                "path": ["email", "university"]
                                            },
                                            {
                                                "id": "fourth",
                                                "path": ["email", "personal"]
                                            }
                                        ],
                                       "claim_sets": [["first", "second"], ["third", "fourth"]]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_2()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_dcql_with_multiple_credentials()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "id": "first",
                                                "path": ["name"]
                                            },
                                            {
                                                "id": "second",
                                                "path": ["email", "work"]
                                            },
                                            {
                                                "id": "third",
                                                "path": ["email", "university"]
                                            },
                                            {
                                                "id": "fourth",
                                                "path": ["email", "personal"]
                                            }
                                        ],
                                       "claim_sets": [["first", "second"], ["third", "fourth"]]
                                    },
                                    {
                                        "id": "pid2",
                                        "format": "dc+sd-jwt",
                                        "meta": {
                                            "vct_values": ["https://credentials.example.com/employee_credential"]
                                        },
                                        "claims": [
                                            {
                                                "id": "first",
                                                "path": ["name"]
                                            },
                                            {
                                                "id": "second",
                                                "path": ["email"]
                                            }
                                        ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_2(), credential_4()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_dcql_with_credential_sets() -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "id": "first",
                                                "path": ["name"]
                                            },
                                            {
                                                "id": "second",
                                                "path": ["email", "work"]
                                            },
                                            {
                                                "id": "third",
                                                "path": ["email", "university"]
                                            },
                                            {
                                                "id": "fourth",
                                                "path": ["email", "personal"]
                                            }
                                        ],
                                       "claim_sets": [["first", "second"], ["third", "fourth"]]
                                    },
                                    {
                                        "id": "pid2",
                                        "format": "dc+sd-jwt",
                                        "meta": {
                                            "vct_values": ["https://credentials.example.com/employee_credential"]
                                        },
                                        "claims": [
                                            {
                                                "id": "first",
                                                "path": ["name"]
                                            },
                                            {
                                                "id": "second",
                                                "path": ["email", "work"]
                                            }
                                        ]
                                    },
                                    {
                                        "id": "pid3",
                                        "format": "dc+sd-jwt",
                                        "meta": {
                                            "vct_values": ["https://credentials.example.com/employee_credential"]
                                        },
                                        "claims": [
                                            {
                                                "id": "first",
                                                "path": ["name"]
                                            },
                                            {
                                                "id": "second",
                                                "path": ["email"]
                                            }
                                        ]
                                    }
                                ],
                                "credential_sets": [
                                    {
                                        "options": [["pid", "pid3"], ["pid2", "pid3"]],
                                        "required": true
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_2(), credential_4()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
            pub fn presentation_test_case_for_dcql_with_claim_values_empty_result()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "id": "first",
                                                "path": ["name"],
                                                "values": ["John"]
                                            },
                                            {
                                                "id": "second",
                                                "path": ["email", "personal"],
                                                "values": ["non-fitting-email"]
                                            }
                                        ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_dcql_with_claim_values_some_result()
            -> PresentationTestCase {
                let credential_data: Vec<Claims> = vec![
                    credential_1(),
                    credential_2(),
                    credential_3(),
                    credential_4(),
                ];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {},
                                        "claims": [
                                            {
                                                "id": "first",
                                                "path": ["name"],
                                                "values": ["Mike", "some-name"]
                                            },
                                            {
                                                "id": "second",
                                                "path": ["email", "personal"],
                                                "values": ["personal@mike.com", "non-used-email"]
                                            }
                                        ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![credential_2()],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_empty_result() -> PresentationTestCase {
                let cred1: Claims = json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "name": "John",
                })
                .try_into()
                .unwrap();
                let cred2: Claims = json!({
                    "vct": "some_vct",
                    "id": "John",
                    "email": "some_email@email.com",
                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred1.clone(), cred2.clone()];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {},
                                        "claims": [
                                            {
                                              "id": "DmPO9iQ0efi4DiWNv5DPTHLI7wHc4BFM0HuA2XMupVYZ",
                                              "path": [
                                                "name"
                                              ]
                                            },
                                            {
                                              "id": "v6G66WUx4WxX6sJJocKIsX1m3DGNJxoaAY8WjYDPJ7wZ",
                                              "path": [
                                                "email"
                                              ]
                                            }
                                          ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }

            pub fn presentation_test_case_for_empty_result2() -> PresentationTestCase {
                let cred1: Claims = json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "address": {
                        "city": "some-city",
                        "street": "some-street",
                    }
                })
                .try_into()
                .unwrap();
                let credential_data: Vec<Claims> = vec![cred1.clone()];
                let dcql = r#"
                            {
                                "credentials": [
                                    {
                                        "id": "pid",
                                        "format": "dc+sd-jwt",
                                        "meta": {},
                                        "claims": [
                                            {
                                              "id": "DmPO9iQ0efi4DiWNv5DPTHLI7wHc4BFM0HuA2XMupVYZ",
                                              "path": [
                                                "address",
                                                "city"
                                              ]
                                            },
                                            {
                                              "id": "v6G66WUx4WxX6sJJocKIsX1m3DGNJxoaAY8WjYDPJ7wZ",
                                              "path": [
                                                "address",
                                                "zip"
                                              ]
                                            }
                                          ]
                                    }
                                ]
                            }
                "#;
                let auth_request = PresentationTestCase::build_auth_request_for_dcql(dcql);
                let presentation_submission =
                    serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

                PresentationTestCase {
                    credential_format: ClaimFormatDesignation::SdJwtVc,
                    request: auth_request,
                    credential_data,
                    expected_credential_data: vec![],
                    presentation_submission,
                    response_metadata: Default::default(),
                    transaction_data: None,
                }
            }
        }
    }

    pub mod multi_presentation {
        use crate::nonce::Nonce;
        use crate::vc::claims::Claims;
        use crate::vc::oid4vp::api::TransactionDataItem;
        use crate::vc::oid4vp::tests::fixtures::NONCE;
        use crate::vc::oid4vp::tests::utils::{PresentationTestCase, VerificationTestCase};
        use crate::vc::oid4vp::{
            AuthResponseOptions, PresentationSession, ResolvedAuthRequest,
            ResolvedPresentationQuery, ResponseMode, ResponseType, TransactionDataResponse,
        };
        use crate::vc::presentation_exchange::{
            PresentationDefinition, PresentationSubmission, SubmissionRequirement,
            SubmissionRequirementBase, SubmissionRequirementObject, SubmissionRequirementPick,
        };
        use base64::Engine;
        use base64::prelude::BASE64_URL_SAFE_NO_PAD;
        use bip32::secp256k1::sha2;
        use bip32::secp256k1::sha2::Digest;
        use openid4vp::core::authorization_request::parameters::{HashAlgorithm, TransactionData};
        use openid4vp::core::credential_format::ClaimFormatDesignation;
        use openid4vp::core::response::parameters::{
            TransactionDataHashes, TransactionDataHashesAlg,
        };
        use serde_json::json;
        use url::Url;

        const PRESENTATION_DEFINITION: &str = r#"{
           "id":"327ad171-c80a-485b-b098-50d7ad278ef6",
           "input_descriptors":[
              {
                 "id":"Identity-1",
                 "name":"Identity VC",
                 "purpose":"We want an identity",
                 "format":{
                    "dc+sd-jwt":{
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
                 "constraints":{
                    "fields":[
                       {
                          "path":[
                             "$.vct"
                          ],
                          "filter":{
                             "type":"string",
                             "const":"https://credentials.example.com/identity_credential"
                          }
                       },
                       {
                          "path":[
                            "$.name",
                            "$.surname",
                            "$.date"
                          ]
                       }
                    ]
                 }
              },
              {
                 "id":"SD_JWT_cred",
                 "name":"Identity VC",
                 "purpose":"We want an identity",
                 "format":{
                    "dc+sd-jwt":{
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
                 "constraints":{
                    "fields":[
                       {
                          "path":[
                             "$.vct"
                          ],
                          "filter":{
                             "type":"string",
                             "const":"https://credentials.example.com/employee_credential"
                          }
                       },
                       {
                          "path":[
                            "$.name",
                            "$.email.personal"
                          ]
                       }
                    ]
                 }
              }
           ]
        }"#;

        const PRESENTATION_SUBMISSION: &str = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "definition_id": "327ad171-c80a-485b-b098-50d7ad278ef6",
            "descriptor_map": [
                {
                    "id": "Identity-1",
                    "format": "dc+sd-jwt",
                    "path": "$[0]"
                },
                {
                    "id": "SD_JWT_cred",
                    "format": "dc+sd-jwt",
                    "path": "$[1]"
                }
            ]
        }"#;

        const AUTH_REQUEST: &str = r#"
        {
           "client_id":"decentralized_identifier:did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX",
           "state": null,
           "presentation_definition": {
               "id":"327ad171-c80a-485b-b098-50d7ad278ef6",
               "input_descriptors":[
                  {
                     "id":"Identity-1",
                     "name":"Identity VC",
                     "purpose":"We want an identity",
                     "format":{
                        "dc+sd-jwt":{
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
                     "constraints":{
                        "fields":[
                           {
                              "path":[
                                 "$.vct"
                              ],
                              "filter":{
                                 "type":"string",
                                 "const":"https://credentials.example.com/identity_credential"
                              }
                           },
                           {
                              "path":[
                                "$.name",
                                "$.surname",
                                "$.date"
                              ]
                           }
                        ]
                     }
                  },
                  {
                     "id":"SD_JWT_cred",
                     "name":"Identity VC",
                     "purpose":"We want an identity",
                     "format":{
                        "dc+sd-jwt":{
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
                     "constraints":{
                        "fields":[
                           {
                              "path":[
                                 "$.vct"
                              ],
                              "filter":{
                                 "type":"string",
                                 "const":"https://credentials.example.com/employee_credential"
                              }
                           },
                           {
                             "path":[
                               "$.name",
                               "$.email.personal"
                             ]
                          }
                        ]
                     }
                  }
               ]
            },
           "nonce":"n0NcE",
           "response_mode":"direct_post",
           "response_type": "vp_token",
           "response_uri":"http://127.0.0.1:55796/auth",
           "client_metadata": {
                "vp_formats_supported": {
                    "dc+sd-jwt": {
                        "sd-jwt_alg_values": ["EdDSA", "ES256"],
                        "kb-jwt_alg_values": ["EdDSA", "ES256"]
                    }
                }
           }
        }"#;

        const AUTH_REQUEST_WITH_STATE: &str = r#"
        {
           "client_id":"decentralized_identifier:did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX",
           "state": "1d8b0d93-86e8-4135-87d4-524bb0500bf3",
           "presentation_definition": {
               "id":"327ad171-c80a-485b-b098-50d7ad278ef6",
               "input_descriptors":[
                  {
                     "id":"Identity-1",
                     "name":"Identity VC",
                     "purpose":"We want an identity",
                     "format":{
                        "dc+sd-jwt":{
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
                     "constraints":{
                        "fields":[
                           {
                              "path":[
                                 "$.vct"
                              ],
                              "filter":{
                                 "type":"string",
                                 "const":"https://credentials.example.com/identity_credential"
                              }
                           },
                           {
                              "path":[
                                "$.name",
                                "$.surname",
                                "$.date"
                              ]
                           }
                        ]
                     }
                  },
                  {
                     "id":"SD_JWT_cred",
                     "name":"Identity VC",
                     "purpose":"We want an identity",
                     "format":{
                        "dc+sd-jwt":{
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
                     "constraints":{
                        "fields":[
                           {
                              "path":[
                                 "$.vct"
                              ],
                              "filter":{
                                 "type":"string",
                                 "const":"https://credentials.example.com/employee_credential"
                              }
                           },
                           {
                             "path":[
                               "$.name",
                               "$.email.personal"
                             ]
                          }
                        ]
                     }
                  }
               ]
            },
           "nonce":"n0NcE",
           "response_mode":"direct_post",
           "response_type": "vp_token",
           "response_uri":"http://127.0.0.1:55796/auth",
           "client_metadata": {
                "vp_formats_supported": {
                    "dc+sd-jwt": {
                        "sd-jwt_alg_values": ["EdDSA", "ES256"],
                        "kb-jwt_alg_values": ["EdDSA", "ES256"]
                    }
                }
           }
        }"#;

        pub fn presentation_definition() -> PresentationDefinition {
            serde_json::from_str(PRESENTATION_DEFINITION).unwrap()
        }

        pub fn presentation_submission() -> PresentationSubmission {
            serde_json::from_str(PRESENTATION_SUBMISSION).unwrap()
        }

        pub fn submission_requirements(pick_count: usize) -> Vec<SubmissionRequirement> {
            vec![SubmissionRequirement::Pick(SubmissionRequirementPick {
                submission_requirement: SubmissionRequirementBase::From {
                    from: "A".to_string(),
                    submission_requirement_base: SubmissionRequirementObject {
                        name: Some("Identity proof".to_string()),
                        purpose: None,
                        property_set: None,
                    },
                },
                count: Some(pick_count),
                min: None,
                max: None,
            })]
        }

        pub fn auth_request() -> ResolvedAuthRequest {
            serde_json::from_str(AUTH_REQUEST).unwrap()
        }

        pub fn auth_request_with_state() -> ResolvedAuthRequest {
            serde_json::from_str(AUTH_REQUEST_WITH_STATE).unwrap()
        }

        pub fn credential_data() -> Vec<Claims> {
            vec![
                json!({
                    "vct": "https://credentials.example.com/identity_credential",
                    "name": "John",
                    "surname": "Doe",
                    "date": "09/09/1989",
                })
                .try_into()
                .unwrap(),
                json!({
                    "vct": "https://credentials.example.com/employee_credential",
                    "name": "John",
                    "email": {
                        "work": "work@example.com",
                        "personal": "personal@example.com"
                    },
                })
                .try_into()
                .unwrap(),
            ]
        }

        pub fn presentation_session() -> PresentationSession {
            PresentationSession {
                nonce: Nonce::from_secret(NONCE.to_owned()),
                resolved_presentation_query: ResolvedPresentationQuery::PresentationDefinition(
                    presentation_definition(),
                ),
                auth_request_jwt: Default::default(),
            }
        }

        pub fn presentation_test_case() -> PresentationTestCase {
            PresentationTestCase {
                credential_format: ClaimFormatDesignation::SdJwtVc,
                request: auth_request(),
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                response_metadata: Default::default(),
                expected_credential_data: credential_data(),
                transaction_data: None,
            }
        }

        pub fn presentation_test_case_filter_by_path() -> PresentationTestCase {
            let cred1: Claims = json!({
                "vct": "https://credentials.example.com/student_credential_1",
                "name": "Mike",
                "age": 20,
                "address": {
                    "country": "UK",
                    "city": "London"
                }
            })
            .try_into()
            .unwrap();
            let cred2: Claims = json!({
                "vct": "https://credentials.example.com/student_credential_2",
                "name": "John",
                "email": "john@example.com"
            })
            .try_into()
            .unwrap();
            let cred3: Claims = json!({
                "vct": "https://credentials.example.com/student_credential_3",
                "email": "alex@example.com",
                "age": 35
            })
            .try_into()
            .unwrap();
            let credential_data: Vec<Claims> = vec![cred1.clone(), cred2, cred3.clone()];
            let auth_request_str = r#"
            {
               "client_id":"decentralized_identifier:did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX",
               "state": null,
               "presentation_definition": {
                   "id":"327ad171-c80a-485b-b098-50d7ad278ef6",
                   "input_descriptors":[
                      {
                         "id":"Identity-1",
                         "name":"Identity VC",
                         "purpose":"We want an identity",
                         "format":{
                            "dc+sd-jwt":{
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
                         "constraints":{
                            "fields":[
                               {
                                  "path":[
                                    "$.name",
                                    "$.address.country",
                                    "$.address.city"
                                  ]
                               }
                            ]
                         }
                      },
                      {
                         "id":"Identity-2",
                         "name":"Identity VC",
                         "purpose":"We want an identity",
                         "format":{
                            "dc+sd-jwt":{
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
                         "constraints":{
                            "fields":[
                               {
                                 "path":[
                                   "$.age",
                                   "$.email"
                                 ]
                              }
                            ]
                         }
                      }
                   ]
                },
               "nonce":"n0NcE",
               "response_mode":"direct_post",
               "response_type": "vp_token",
               "response_uri":"http://127.0.0.1:55796/auth",
               "client_metadata": {
                    "vp_formats_supported": {
                        "dc+sd-jwt": {
                            "sd-jwt_alg_values": ["EdDSA", "ES256"],
                            "kb-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    }
              }
            }"#;
            let auth_request = serde_json::from_str(auth_request_str).unwrap();

            let presentation_submission_str = r#"{
                "id": "00000000-0000-0000-0000-000000000000",
                "definition_id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                "descriptor_map": [
                    {
                        "id": "Identity-1",
                        "format": "dc+sd-jwt",
                        "path": "$[0]"
                    },
                    {
                        "id": "Identity-2",
                        "format": "dc+sd-jwt",
                        "path": "$[1]"
                    }
                ]
            }"#;
            let presentation_submission =
                serde_json::from_str(presentation_submission_str).unwrap();

            PresentationTestCase {
                credential_format: ClaimFormatDesignation::SdJwtVc,
                request: auth_request,
                expected_credential_data: vec![cred1, cred3],
                credential_data,
                presentation_submission,
                response_metadata: Default::default(),
                transaction_data: None,
            }
        }

        pub fn presentation_test_case_with_state() -> PresentationTestCase {
            PresentationTestCase {
                credential_format: ClaimFormatDesignation::SdJwtVc,
                request: auth_request_with_state(),
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                response_metadata: Default::default(),
                expected_credential_data: credential_data(),
                transaction_data: None,
            }
        }

        pub fn verification_test_case() -> VerificationTestCase {
            VerificationTestCase {
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                session: presentation_session(),
            }
        }

        pub fn auth_response_options(
            submission_uri: Url,
            state: Option<String>,
        ) -> AuthResponseOptions {
            AuthResponseOptions {
                type_: ResponseType::VpToken,
                mode: ResponseMode::DirectPost,
                submission_uri,
                state,
            }
        }

        pub fn transaction_data_items() -> Vec<TransactionDataItem> {
            vec![
                TransactionDataItem {
                    type_: "some_type".to_string(),
                    credential_ids: Vec::from(["1".to_string(), "2".to_string()]),
                    transaction_data_hashes_alg: Some(vec![
                        HashAlgorithm::Sha256,
                        HashAlgorithm::Sha512,
                    ]),
                },
                TransactionDataItem {
                    type_: "some_type2".to_string(),
                    credential_ids: Vec::from(["11".to_string(), "22".to_string()]),
                    transaction_data_hashes_alg: None,
                },
            ]
        }

        pub fn transaction_data() -> TransactionData {
            TransactionData(
                transaction_data_items()
                    .iter()
                    .map(|i| i.to_owned().into_base64url_encoded().unwrap())
                    .collect(),
            )
        }
        pub fn transaction_data_response() -> TransactionDataResponse {
            let transaction_data = transaction_data_items();
            let hash_alg = HashAlgorithm::Sha256;
            // json_str -> base64 -> hash -> base64
            let encoded1 = BASE64_URL_SAFE_NO_PAD
                .encode(serde_json::to_string(transaction_data.first().unwrap()).unwrap());
            let encoded2 = BASE64_URL_SAFE_NO_PAD
                .encode(serde_json::to_string(transaction_data.get(1).unwrap()).unwrap());
            let hash1 = sha2::Sha256::digest(encoded1.as_bytes());
            let hash2 = sha2::Sha256::digest(encoded2.as_bytes());
            let encoded1 = BASE64_URL_SAFE_NO_PAD.encode(hash1);
            let encoded2 = BASE64_URL_SAFE_NO_PAD.encode(hash2);
            TransactionDataResponse {
                transaction_data_hashes: TransactionDataHashes(vec![encoded1, encoded2]),
                transaction_data_hashes_alg: Some(TransactionDataHashesAlg(HashAlgorithm::Sha256)),
            }
        }
    }
}

pub mod utils {
    use crate::crypto::Key;
    use crate::crypto::{JWK, SSIAlg};
    use crate::did::didkey::DIDKey;
    use crate::did::universal::UniversalResolver;
    use crate::http::{HttpClient, MockHttpClient};
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::inmem::nonce::LocalNonceHandler;
    use crate::inmem::vault::InMemVault;
    use crate::kms::MockKms;
    use crate::kms::{CreateOptions, KeyID, KeyType, Kms};
    use crate::nonce::Nonce;
    use crate::utils::http::test::mock_http_req_async_predicate;
    use crate::utils::test_utils;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::utils::test_utils::failed_signer_key;
    use crate::vault::{CredentialEntry, Vault};
    use crate::vc;
    use crate::vc::claims::Claims;
    use crate::vc::core::api::PresentationRestrictionValue;
    use crate::vc::core::{HolderBinder, KeyMetadata, ProofOfPossessionMetadata};
    use crate::vc::formats::json_ld_vc::JsonLdAPI;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VPMetadata};
    use crate::vc::formats::{json_ld_vc, sd_jwt_vc};
    use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
    use crate::vc::oid4vp::holder::HolderService;
    use crate::vc::oid4vp::jwe_utils::WrapperForES256Handle;
    use crate::vc::oid4vp::signer::Signer;
    use crate::vc::oid4vp::tests::fixtures::multi_presentation::{
        transaction_data_items, transaction_data_response,
    };
    use crate::vc::oid4vp::tests::fixtures::single_presentation::sd_jwt::client_metadata_no_keys;
    use crate::vc::oid4vp::tests::fixtures::{CREDENTIAL_ID, VERIFIER_URL};
    use crate::vc::oid4vp::verifier::VerifierService;
    use crate::vc::oid4vp::{
        AuthorizationResponseMetadata, AuthorizationResponseObject, ClientId, ClientMetadata,
        CredentialMapping, Holder, PresentationSession, ResolvedAuthRequest, ResponseType,
        TransactionDataResponse, Verifier,
    };
    use crate::vc::presentation_exchange::PresentationSubmission;
    use crate::vc::{
        ClaimFormatDesignation, Credential, JsonLdAPIVCMetadata, VCFormatsAPI, VCMetadata,
        presentation_exchange,
    };
    use async_trait::async_trait;
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use bip32::secp256k1::sha2;
    use bip32::secp256k1::sha2::Digest;
    use iref::UriBuf;
    use oauth2::http::{Method, Request, Response, StatusCode};
    use one_crypto::jwe::PrivateKeyAgreementHandle;
    use one_crypto::jwe::decrypt_jwe_payload;
    use openid4vp::core::authorization_request::parameters::{HashAlgorithm, TransactionData};
    use openid4vp::core::authorization_request::verification::RequestVerifier;
    use openid4vp::core::metadata::parameters::SubjectSyntaxTypesSupported;
    use openid4vp::core::response::PostRedirection;
    use openid4vp::core::response::parameters::{
        IdToken, TransactionDataHashes, TransactionDataHashesAlg,
    };
    use openid4vp::core::util::http::AsyncHttpClient;
    use openid4vp::wallet::{IdTokenParams, Wallet};
    use sd_jwt_rs::SDJWTSerializationFormat;
    use sd_jwt_rs::utils::decode_sd_jwt;
    use serde_json::{Value, json};
    use ssi::dids::DIDURLBuf;
    use ssi::json_ld::IriRefBuf;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;
    use url::Url;

    pub struct PresentationTestCase {
        pub credential_format: ClaimFormatDesignation,
        pub request: ResolvedAuthRequest,
        pub credential_data: Vec<Claims>,
        pub presentation_submission: PresentationSubmission,
        pub response_metadata: AuthorizationResponseMetadata,
        pub expected_credential_data: Vec<Claims>,
        pub transaction_data: Option<TransactionData>,
    }

    struct MockAuthResponseHelperParams {
        credential_format: ClaimFormatDesignation,
        expected_credential_data: Vec<Claims>,
        expected_presentation_submission: PresentationSubmission,
        client_id: String,
        nonce: Nonce,
        response_type: ResponseType,
        request: String,
        expected_state: Option<String>,
        transaction_data: Option<TransactionData>,
    }

    impl PresentationTestCase {
        pub fn mock_http_auth_response_endpoint(
            &self,
            http_client: &mut MockHttpClient,
            claims_to_exclude: Option<&HashMap<String, Vec<String>>>,
        ) {
            let expected_credential_data = self.expected_credential_data.clone();
            let expected_presentation_submission = self.presentation_submission.clone();
            let client_id = self.request.client_id.get_full_id();
            let nonce = self.request.nonce.clone();
            let response_type = self.request.response_type.clone();
            let state = self.request.state.clone();
            let credential_format = self.credential_format.clone();
            let transaction_data = self.transaction_data.clone();

            mock_http_req_async_predicate(
                http_client,
                Method::POST,
                build_url(VERIFIER_URL, "auth"),
                move |request| {
                    Self::mock_http_auth_response_endpoint_helper(MockAuthResponseHelperParams {
                        credential_format: credential_format.clone(),
                        expected_credential_data: expected_credential_data.clone(),
                        expected_presentation_submission: expected_presentation_submission.clone(),
                        client_id: client_id.clone(),
                        nonce: nonce.clone(),
                        response_type: response_type.clone(),
                        request,
                        expected_state: state.clone(),
                        transaction_data: transaction_data.clone(),
                    })
                },
                PostRedirection {
                    redirect_uri: build_url(VERIFIER_URL, "redirect"),
                },
                StatusCode::OK,
                1.into(),
            );
        }

        async fn mock_http_auth_response_endpoint_helper(
            MockAuthResponseHelperParams {
                credential_format,
                expected_credential_data,
                expected_presentation_submission,
                client_id,
                nonce,
                response_type,
                request,
                expected_state,
                transaction_data,
            }: MockAuthResponseHelperParams,
        ) -> bool {
            let form: HashMap<String, String> =
                serde_urlencoded::from_bytes(request.as_bytes()).unwrap();
            let claims;
            let mut presentation_submission: PresentationSubmission;
            let transaction_data_response: Option<TransactionDataResponse>;
            if form.contains_key::<String>(&String::from("response")) {
                let response = form.get::<String>(&String::from("response")).unwrap();
                let jwk = r#"{
                         "kty": "EC",
                         "crv": "P-256",
                         "x": "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
                         "y": "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY",
                         "d": "rs9veoNnfQCH7kfsAis_nAHtpcEghiAzKry8R-de0eA"
                     }"#;
                let kh = wrap_p256_private_key(jwk);

                let payload = decrypt_jwe_payload(response, &kh).await.unwrap();
                let claim_set: Value = serde_json::from_slice(payload.as_slice()).unwrap();
                let Value::Object(claim_set) = claim_set else {
                    panic!("claim set must be Value::Object")
                };
                presentation_submission = serde_json::from_value(
                    claim_set.get("presentation_submission").unwrap().clone(),
                )
                .unwrap();
                let transaction_data_hashes = claim_set
                    .get("transaction_data_hashes")
                    .cloned()
                    .and_then(|v| serde_json::from_value(v).ok());
                let transaction_data_hashes_alg = claim_set
                    .get("transaction_data_hashes_alg")
                    .cloned()
                    .and_then(|v| serde_json::from_value(v).ok());
                transaction_data_response =
                    transaction_data_hashes.map(|tdh| TransactionDataResponse {
                        transaction_data_hashes: tdh,
                        transaction_data_hashes_alg,
                    });
                let claim_set = claim_set
                    .into_iter()
                    .map(|(k, v)| (k.to_owned().to_string(), v.to_owned().to_string()))
                    .collect::<HashMap<String, String>>();
                claims = Self::extract_claims(&claim_set);
            } else {
                claims = Self::extract_claims(&form);
                presentation_submission =
                    serde_json::from_str(&form["presentation_submission"]).unwrap();

                let transaction_data_hashes = form
                    .get("transaction_data_hashes")
                    .cloned()
                    .and_then(|v| serde_json::from_str(v.as_str()).ok());
                let transaction_data_hashes_alg = form
                    .get("transaction_data_hashes_alg")
                    .cloned()
                    .and_then(|v| serde_json::from_str(v.as_str()).ok());
                transaction_data_response =
                    transaction_data_hashes.map(|tdh| TransactionDataResponse {
                        transaction_data_hashes: tdh,
                        transaction_data_hashes_alg,
                    });
            }

            if let Some(tdr) = transaction_data_response {
                let transaction_data = transaction_data.unwrap();
                let hash1 = sha2::Sha256::digest(transaction_data.0.first().unwrap().as_bytes());
                let hash2 = sha2::Sha256::digest(transaction_data.0.get(1).unwrap().as_bytes());
                let encoded1 = BASE64_URL_SAFE_NO_PAD.encode(hash1);
                let encoded2 = BASE64_URL_SAFE_NO_PAD.encode(hash2);
                assert_eq!(
                    tdr.transaction_data_hashes.0.first().unwrap().as_str(),
                    encoded1.as_str()
                );
                assert_eq!(
                    tdr.transaction_data_hashes.0.get(1).unwrap().as_str(),
                    encoded2.as_str()
                );
            }

            for index in 0..claims.len() {
                validate_claims(
                    &credential_format,
                    claims.get(index).unwrap(),
                    expected_credential_data.get(index).unwrap(),
                )
            }

            presentation_submission = PresentationSubmission::new(
                uuid::Uuid::default(),
                presentation_submission.definition_id().to_owned(),
                presentation_submission.descriptor_map().to_owned(),
            );

            assert_eq!(presentation_submission, expected_presentation_submission);

            if response_type == ResponseType::VpTokenIdToken {
                let id_token: IdToken = form
                    .get("id_token")
                    .unwrap()
                    .to_string()
                    .try_into()
                    .unwrap();
                let id_token = id_token.parsed_body();

                assert_eq!(id_token.nonce, nonce.secret());
                assert_eq!(
                    id_token.audience,
                    ClientId::new(client_id).unwrap().get_id()
                )
            }

            let state = form.get("state");
            assert_eq!(expected_state.as_ref(), state);

            true
        }
        pub async fn prepare_vault(&self, kms: &LocalKms) -> InMemVault {
            let vault = InMemVault::new();

            // Save credentials
            let holder_key = kms
                .create_and_handle(KeyType::P256, CreateOptions::default())
                .await
                .unwrap();
            self.store_creds(&vault, holder_key).await;

            vault
        }

        pub async fn store_creds(&self, vault: &InMemVault, holder_key: (KeyID, KeyHandle)) {
            let (holder_kid, holder_key_handle) = holder_key;

            match &self.credential_format {
                ClaimFormatDesignation::SdJwtVc => {
                    for claims in &self.credential_data {
                        let (sd_jwt_plain, did_url) =
                            create_sd_jwt_vc(claims, &holder_key_handle).await;
                        let credential = Credential::SdJwt(sd_jwt_plain);
                        let metadata = DefaultMetadataProcessor::resolve_metadata(
                            &credential,
                            KeyMetadata {
                                did_url,
                                kid: holder_kid.to_owned(),
                            },
                        )
                        .unwrap();

                        let res = vault
                            .store_credential(credential.clone(), &metadata)
                            .await
                            .unwrap();
                    }
                }
                ClaimFormatDesignation::LdpVc => {
                    for claims in &self.credential_data {
                        let (ldp_vc_plain, did_url) =
                            create_json_ld_vc(claims, &holder_key_handle).await;
                        let credential = Credential::LdpVc(ldp_vc_plain);
                        let metadata = DefaultMetadataProcessor::resolve_metadata(
                            &credential,
                            KeyMetadata {
                                did_url,
                                kid: holder_kid.to_owned(),
                            },
                        )
                        .unwrap();

                        let res = vault
                            .store_credential(credential.clone(), &metadata)
                            .await
                            .unwrap();
                    }
                }
                _ => {}
            }
        }

        pub async fn build_credential_mapping(
            &self,
            holder_key: (KeyID, KeyHandle),
        ) -> CredentialMapping {
            let (kid, key_handle) = holder_key;
            let inputs = presentation_exchange::split_to_inputs_for_pd(
                &self
                    .request
                    .resolved_presentation_query
                    .get_presentation_definition()
                    .unwrap(),
                None,
            )
            .unwrap();

            let mut result = CredentialMapping::new();

            for input in inputs {
                match &self.credential_format {
                    ClaimFormatDesignation::SdJwtVc => {
                        let claims = self
                            .credential_data
                            .iter()
                            .find(|claim| {
                                let vct = claim["vct"].as_str().unwrap();
                                input.restrictions.iter().any(|restriction| {
                                    matches!(restriction.value.as_ref(), Some(PresentationRestrictionValue::Const(value)) if value == &vct.to_string())
                                })
                            })
                            .unwrap();

                        let (vc, _) = create_sd_jwt_vc(claims, &key_handle).await;

                        result.insert(
                            input.id,
                            CredentialEntry {
                                credential: Credential::SdJwt(vc),
                                kid: kid.to_string(),
                                id: CREDENTIAL_ID.to_string(),
                            },
                        );
                    }
                    ClaimFormatDesignation::LdpVc => {
                        let claims = self.credential_data
                        .iter()
                        .find(|claim| {
                            let type_ = claim["type"].as_vec().unwrap();
                            let types: Vec<&str> =
                                type_.iter().map(|ty| ty.as_str().unwrap()).collect();
                            input.restrictions.iter().any(|restriction| {
                                matches!(restriction.value.as_ref(), Some(PresentationRestrictionValue::Const(value)) if types.contains(&value.as_str()))
                            })
                        })
                        .unwrap();

                        let (vc, _) = create_json_ld_vc(claims, &key_handle).await;

                        result.insert(
                            input.id,
                            CredentialEntry {
                                credential: Credential::LdpVc(vc),
                                kid: kid.to_string(),
                                id: CREDENTIAL_ID.to_string(),
                            },
                        );
                    }
                    _ => {}
                }
            }

            result
        }

        pub fn extract_claims(form: &HashMap<String, String>) -> Vec<Claims> {
            let vp_token = form.get("vp_token").unwrap();
            let vp_token_value: Value =
                serde_json::from_str(vp_token).unwrap_or(serde_json::to_value(vp_token).unwrap());

            match vp_token_value {
                Value::String(token) => {
                    let res = decode_sd_jwt(token, SDJWTSerializationFormat::Compact);
                    vec![res.unwrap().try_into().unwrap()]
                }
                Value::Array(tokens) => tokens
                    .into_iter()
                    .map(|value| {
                        decode_sd_jwt(
                            value.as_str().unwrap().to_string(),
                            SDJWTSerializationFormat::Compact,
                        )
                        .unwrap()
                    })
                    .map(|val| val.try_into().unwrap())
                    .collect(),
                _ => panic!("Invalid VP token format: {:?}", vp_token_value),
            }
        }

        pub fn build_auth_request(format: &str, constraints: &str) -> ResolvedAuthRequest {
            let auth_request_str = format!(
                r#"{{
                  "client_id": "decentralized_identifier:did:key:zDnaehgaHKAP7LAA3Kwa4FjXjJ1G3BcaHqr5gfRySJcGDgBtV",
                  "state": null,
                  "presentation_definition": {{
                    "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                    "input_descriptors": [
                      {{
                        "id": "Identity-1",
                        "name": "Identity VC",
                        "purpose": "We want an identity",
                        "format": {format},
                        "constraints": {constraints}
                      }}
                    ]
                  }},
                  "nonce": "nonce",
                  "response_mode": "direct_post",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                "client_metadata": {{
                "vp_formats_supported": {{
                    "dc+sd-jwt": {{
                        "sd-jwt_alg_values": ["EdDSA", "ES256"],
                        "kb-jwt_alg_values": ["EdDSA", "ES256"]
                    }}
                }}
              }}
            }}"#
            );

            serde_json::from_str(&auth_request_str).unwrap()
        }

        pub fn build_auth_request_for_dcql(dcql: &str) -> ResolvedAuthRequest {
            let auth_request_str = format!(
                r#"{{
                  "client_id": "decentralized_identifier:did:key:zDnaehgaHKAP7LAA3Kwa4FjXjJ1G3BcaHqr5gfRySJcGDgBtV",
                  "state": null,
                  "dcql_query": {dcql},
                  "nonce": "nonce",
                  "response_mode": "direct_post",
                  "response_type": "vp_token",
                  "response_uri": "http://127.0.0.1:55796/auth",
                "client_metadata": {{
                "vp_formats_supported": {{
                    "dc+sd-jwt": {{
                        "sd-jwt_alg_values": ["EdDSA", "ES256"],
                        "kb-jwt_alg_values": ["EdDSA", "ES256"]
                    }}
                }}
              }}
            }}"#
            );

            serde_json::from_str(&auth_request_str).unwrap()
        }
    }

    #[derive(Clone)]
    pub struct VerificationTestCase {
        pub credential_data: Vec<Claims>,
        pub presentation_submission: PresentationSubmission,
        pub session: PresentationSession,
    }

    impl VerificationTestCase {
        pub async fn vp_token(&self, nonce: &Nonce, verifier_id: &str) -> Value {
            let kms = LocalKms::new();
            let (_, holder_key_handle) = kms
                .create_and_handle(KeyType::P256, CreateOptions::default())
                .await
                .unwrap();

            let mut presentations: Vec<sd_jwt_vc::Presentation> = vec![];
            for claims in self.credential_data.iter() {
                let (vc, _) = create_sd_jwt_vc(claims, &holder_key_handle).await;
                let vp = create_sd_jwt_vp(
                    &vc,
                    claims.clone().try_into().unwrap(),
                    nonce,
                    verifier_id,
                    &holder_key_handle,
                )
                .await;
                presentations.push(vp);
            }

            if presentations.len() == 1 {
                json!(presentations.first().unwrap())
            } else {
                json!(presentations)
            }
        }

        pub async fn auth_response_with_transaction_data_response(
            &self,
            nonce: &Nonce,
            verifier_id: &str,
        ) -> AuthorizationResponseObject {
            AuthorizationResponseObject {
                vp_token: self.vp_token(nonce, verifier_id).await,
                presentation_submission: Some(self.presentation_submission.clone()),
                id_token: None,
                state: None,
                transaction_data_response: Some(transaction_data_response()),
            }
        }

        pub async fn auth_response_without_transaction_data_response(
            &self,
            nonce: &Nonce,
            verifier_id: &str,
        ) -> AuthorizationResponseObject {
            AuthorizationResponseObject {
                vp_token: self.vp_token(nonce, verifier_id).await,
                presentation_submission: Some(self.presentation_submission.clone()),
                id_token: None,
                state: None,
                transaction_data_response: None,
            }
        }

        pub async fn auth_response_with_wrong_transaction_data_response(
            &self,
            nonce: &Nonce,
            verifier_id: &str,
        ) -> AuthorizationResponseObject {
            let mut transaction_data_response = transaction_data_response();
            transaction_data_response.transaction_data_hashes = TransactionDataHashes(vec![
                transaction_data_response
                    .transaction_data_hashes
                    .0
                    .first()
                    .unwrap()
                    .clone(),
                "wrong_hash".to_string(),
            ]);
            AuthorizationResponseObject {
                vp_token: self.vp_token(nonce, verifier_id).await,
                presentation_submission: Some(self.presentation_submission.clone()),
                id_token: None,
                state: None,
                transaction_data_response: Some(transaction_data_response),
            }
        }

        pub async fn auth_response_with_wrong_transaction_data(
            &self,
            nonce: &Nonce,
            verifier_id: &str,
        ) -> AuthorizationResponseObject {
            let transaction_data = transaction_data_items();
            let hash_alg = HashAlgorithm::Sha256;
            // json_str -> base64 -> hash -> base64
            let encoded1 = BASE64_URL_SAFE_NO_PAD
                .encode(serde_json::to_string(transaction_data.first().unwrap()).unwrap());
            let encoded2 = BASE64_URL_SAFE_NO_PAD
                .encode(serde_json::to_string(transaction_data.get(1).unwrap()).unwrap());
            let hash1 = sha2::Sha256::digest(encoded1.as_bytes());
            let hash2 = sha2::Sha256::digest(encoded2.as_bytes());
            let encoded1 = BASE64_URL_SAFE_NO_PAD.encode(hash1);
            let encoded2 = BASE64_URL_SAFE_NO_PAD.encode(hash2);

            AuthorizationResponseObject {
                vp_token: self.vp_token(nonce, verifier_id).await,
                presentation_submission: Some(self.presentation_submission.clone()),
                id_token: None,
                state: None,
                transaction_data_response: Some(TransactionDataResponse {
                    transaction_data_hashes: TransactionDataHashes(vec![encoded1, encoded2]),
                    transaction_data_hashes_alg: Some(TransactionDataHashesAlg(hash_alg)),
                }),
            }
        }

        pub async fn auth_response_with_id_token(
            &self,
            nonce: &Nonce,
            verifier_id: &str,
            id_token_params: IdTokenParams,
        ) -> AuthorizationResponseObject {
            let mut auth_resp = self
                .auth_response_with_transaction_data_response(nonce, verifier_id)
                .await;
            auth_resp.id_token = Some(generate_did_based_id_token(id_token_params).await);

            auth_resp
        }
    }

    pub async fn holder_service(
        http_client: impl HttpClient,
        kms: LocalKms,
        vault: InMemVault,
    ) -> impl Holder {
        let http_client = Arc::new(http_client);
        let inner = vc::core::HolderService::new(
            kms.clone(),
            vault,
            vc::core::HolderMetadata {
                client_id: "client_id".to_string(),
                pop: ProofOfPossessionMetadata {
                    lifetime: time::Duration::minutes(5),
                    not_before: None,
                },
            },
            UniversalResolver::default(),
            http_client.clone(),
        );

        HolderService::new(
            inner,
            http_client,
            kms,
            UniversalResolver::default(),
            None,
            None,
        )
    }

    pub async fn request_verifier(
        http_client: impl HttpClient,
        kms: LocalKms,
        vault: InMemVault,
    ) -> impl RequestVerifier {
        let http_client = Arc::new(http_client);
        let inner = vc::core::HolderService::new(
            kms.clone(),
            vault,
            vc::core::HolderMetadata {
                client_id: "client_id".to_string(),
                pop: ProofOfPossessionMetadata {
                    lifetime: time::Duration::minutes(5),
                    not_before: None,
                },
            },
            UniversalResolver::default(),
            http_client.clone(),
        );

        HolderService::new(
            inner,
            http_client,
            kms,
            UniversalResolver::default(),
            None,
            None,
        )
    }

    type TestVerifierService = VerifierService<
        vc::core::VerifierService,
        KeyHandle,
        LocalKms,
        LocalNonceHandler,
        MockHttpClient,
    >;

    async fn create_verifier_service(invalid_key_id: bool) -> (TestVerifierService, String) {
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceHandler::default();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let mut key_metadata = key_metadata;

        if invalid_key_id {
            key_metadata.kid = "invalid_key_id".to_string();
        }

        let inner = vc::core::VerifierService::new(&did, UniversalResolver::default());
        let client_metadata = generate_client_metadata(&kms).await;

        let verifier = VerifierService::new(
            inner,
            kms,
            nonce_gen,
            MockHttpClient::new(),
            did.clone(),
            key_metadata,
            UniversalResolver::default(),
            Some(client_metadata),
        );

        (verifier, did.clone())
    }

    pub async fn verifier_service() -> (TestVerifierService, String) {
        create_verifier_service(false).await
    }

    pub async fn verifier_service_with_invalid_kid() -> (
        VerifierService<
            vc::core::VerifierService,
            KeyHandle,
            LocalKms,
            LocalNonceHandler,
            MockHttpClient,
        >,
        String,
    ) {
        create_verifier_service(true).await
    }

    pub async fn generate_client_metadata(kms: &LocalKms) -> ClientMetadata {
        let key = kms
            .create(KeyType::P256, CreateOptions::default())
            .await
            .unwrap();
        let kh = kms.get(&key).await.unwrap();
        let jwk = kh.jwk().unwrap();
        let jwk = JWK {
            key_id: Some(key),
            public_key_use: Some("enc".to_string()),
            algorithm: Some(SSIAlg::ES256),
            ..jwk
        };
        let jwk = serde_json::to_value(&jwk).unwrap();
        let Value::Object(jwk) = jwk else {
            panic!("The jwk is not an object");
        };

        let sub_syntax_types = SubjectSyntaxTypesSupported(vec!["did:key".to_string()]);
        let mut client_metadata = client_metadata_no_keys();
        client_metadata.0.insert(sub_syntax_types);
        let mut jwks = client_metadata.jwks().unwrap().unwrap();
        jwks.keys.push(jwk.clone());
        client_metadata.0.insert(jwks);

        client_metadata
    }

    pub async fn verifier_service_with_signer_error() -> (impl Verifier, String) {
        let kms = LocalKms::new();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;
        let key_handle = kms.get(&key_metadata.kid).await.unwrap();

        let mut kms_mock = MockKms::new();
        kms_mock
            .expect_get()
            .returning(move |_| Ok(failed_signer_key(key_handle.clone())));

        let verifier = VerifierService::new(
            vc::core::VerifierService::new(&did, UniversalResolver::default()),
            kms_mock,
            LocalNonceHandler::default(),
            MockHttpClient::new(),
            did.clone(),
            key_metadata,
            UniversalResolver::default(),
            None,
        );

        (verifier, did)
    }

    pub fn build_url(base_url: &str, url_part: &str) -> Url {
        Url::parse(base_url).unwrap().join(url_part).unwrap()
    }

    pub async fn create_sd_jwt_vc(
        claims: &Claims,
        holder_key_handle: &KeyHandle,
    ) -> (sd_jwt_vc::Credential, String) {
        let kms = LocalKms::new();

        let (issuer_did_url, issuer_key_handle) =
            test_utils::create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let did = DIDKey::generate(holder_key_handle.clone()).unwrap();
        let holder_did_url = DIDURLBuf::from_str(&did).unwrap();

        let disclosures: Vec<String> = claims
            .claims()
            .keys()
            .map(|key| format!("$.{}", key))
            .collect();

        let vct = claims["vct"].as_str().unwrap();
        let credential = SdJwtAPI::create_vc(
            claims.clone(),
            (&issuer_did_url, issuer_key_handle),
            (&holder_did_url, holder_key_handle.clone()),
            VCMetadata {
                vct: vct.to_owned(),
                lifetime: time::Duration::days(365),
                disclosures,
                credential_status: None,
            },
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        (credential, holder_did_url.to_string())
    }

    pub async fn create_json_ld_vc(
        claims: &Claims,
        holder_key_handle: &KeyHandle,
    ) -> (json_ld_vc::VC, String) {
        let kms = LocalKms::new();

        let (issuer_did_url, issuer_key_handle) =
            test_utils::create_did_url_and_key_handle(&kms, KeyType::Bls12381).await;

        let did = DIDKey::generate(holder_key_handle.clone()).unwrap();
        let holder_did_url = DIDURLBuf::from_str(&did).unwrap();
        let type_ = claims["type"].as_vec().unwrap();

        let mut vc_metadata = JsonLdAPIVCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/examples/v2").unwrap(),
            ],
            type_
                .iter()
                .map(|claim| claim.as_str().unwrap().to_string())
                .collect(),
            time::Duration::days(5 * 365),
        )
        .unwrap();
        vc_metadata.mandatory_claims = Some(vec!["/type".parse().unwrap()]);
        vc_metadata.credential_id =
            Some(UriBuf::from_str("urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f").unwrap());

        let credential = JsonLdAPI::create_vc(
            claims.clone(),
            (&issuer_did_url, issuer_key_handle),
            (&holder_did_url, holder_key_handle.clone()),
            vc_metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        (credential, holder_did_url.to_string())
    }

    pub async fn create_sd_jwt_vp(
        vc: &sd_jwt_vc::Credential,
        disclosures: Value,
        nonce: &Nonce,
        verifier_id: &str,
        holder_key_handle: &KeyHandle,
    ) -> sd_jwt_vc::Presentation {
        SdJwtAPI::create_vp(
            vc,
            holder_key_handle.clone(),
            VPMetadata {
                disclosures: disclosures.as_object().unwrap().to_owned(),
                holder_binder: Some(HolderBinder {
                    nonce: nonce.to_owned(),
                    verifier_id: verifier_id.to_string(),
                }),
            },
            UniversalResolver::default(),
        )
        .await
        .unwrap()
    }

    pub fn validate_claims(
        credential_format: &ClaimFormatDesignation,
        claims: &Claims,
        expected_credential_data: &Claims,
    ) {
        match credential_format {
            ClaimFormatDesignation::SdJwtVc => {
                let actual_vct = &claims["vct"];

                let expected_claims = expected_credential_data;
                let expected_vct = &expected_claims["vct"];
                assert_eq!(actual_vct, expected_vct);

                for (key, value) in expected_claims.claims() {
                    assert_eq!(&claims[key], value, "Claims: expected {key}: {value}");
                }
            }
            ClaimFormatDesignation::LdpVc => {
                let actual_type = &claims["type"];

                let expected_claims = expected_credential_data;
                let expected_type = &expected_claims["type"];

                assert_eq!(actual_type, expected_type);

                for (key, value) in expected_claims.claims() {
                    assert_eq!(
                        &claims["credentialSubject"][key], value,
                        "Claims: expected {key}: {value}"
                    );
                }
            }
            _ => {}
        }
    }

    pub async fn generate_did_based_id_token(params: IdTokenParams) -> String {
        let http_client = Arc::new(MockHttpClient::new());
        let kms = LocalKms::new();
        let inner = vc::core::HolderService::new(
            kms.clone(),
            InMemVault::new(),
            vc::core::HolderMetadata {
                client_id: "client_id".to_string(),
                pop: ProofOfPossessionMetadata {
                    lifetime: time::Duration::minutes(5),
                    not_before: None,
                },
            },
            UniversalResolver::default(),
            http_client.clone(),
        );

        let holder = HolderService::new(
            inner,
            http_client,
            kms.clone(),
            UniversalResolver::default(),
            None,
            None,
        );
        let (did, metadata) = create_did_and_key_metadata(&kms).await;

        let key = kms.get(&metadata.kid).await.unwrap();

        holder
            .generate_did_based_id_token(
                &metadata.did_url.parse().unwrap(),
                params,
                Signer::new(key).unwrap(),
            )
            .await
            .unwrap()
    }

    #[async_trait]
    impl AsyncHttpClient for MockHttpClient {
        async fn execute(&self, request: Request<Vec<u8>>) -> anyhow::Result<Response<Vec<u8>>> {
            self.async_call(request)
                .await
                .map_err(|e| anyhow::Error::msg(e.to_string()))
        }
    }

    pub fn wrap_p256_private_key(jwk: &str) -> impl PrivateKeyAgreementHandle {
        let key = p256::SecretKey::from_jwk_str(jwk).unwrap();
        WrapperForES256Handle { key }
    }
}
