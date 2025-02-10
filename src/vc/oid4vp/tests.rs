use crate::vc::claims::Claims;

type CredTypeWithClaims = (&'static str, Claims);

pub mod fixtures {
    pub const VERIFIER_URL: &str = "http://127.0.0.1:55796";
    pub const NONCE: &str = "n0NcE";
    pub const CLIENT_ID: &str = "wallet-dev";
    pub const STATE: &str = "1d8b0d93-86e8-4135-87d4-524bb0500bf3";
    pub const REQUEST_URI: &str = "openid4vp://?client_id=did%3Akey%3AzDnaehgaHKAP7LAA3Kwa4FjXjJ1G3BcaHqr5gfRySJcGDgBtV&request_uri=http%3A%2F%2F127.0.0.1%3A55796%2Frequest";
    pub const CREDENTIAL_ID: &str = "abcde";

    pub mod single_presentation {
        use crate::nonce::Nonce;
        use crate::vc::oid4vp::tests::fixtures::NONCE;
        use crate::vc::oid4vp::tests::utils::{PresentationTestCase, VerificationTestCase};
        use crate::vc::oid4vp::tests::CredTypeWithClaims;
        use crate::vc::oid4vp::{PresentationSession, ResolvedAuthRequest};
        use crate::vc::presentation_exchange::{PresentationDefinition, PresentationSubmission};
        use serde_json::json;

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

        pub const AUTH_REQUEST_JWT: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVoZ2FIS0FQN0xBQTNLd2E0RmpYakoxRzNCY2FIcXI1Z2ZSeVNKY0dEZ0J0ViN6RG5hZWhnYUhLQVA3TEFBM0t3YTRGalhqSjFHM0JjYUhxcjVnZlJ5U0pjR0RnQnRWIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJub25jZSI6IjNEYUx3ZGk4OXFEZ3BscFN3QXNwWDZ3V3ptNnBMa3phTjNYdWstYXI1elkiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0cyI6eyJkYytzZC1qd3QiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiXX19fSwiY2xpZW50X2lkIjoiZGlkOmtleTp6RG5hZWhnYUhLQVA3TEFBM0t3YTRGalhqSjFHM0JjYUhxcjVnZlJ5U0pjR0RnQnRWIiwiY2xpZW50X2lkX3NjaGVtZSI6ImRpZCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzI3YWQxNzEtYzgwYS00ODViLWIwOTgtNTBkN2FkMjc4ZWY2IiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLm5hbWUiXSwib3B0aW9uYWwiOnRydWUsInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIn0sInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX0sIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7ImRjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl0sImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXX19fV0sIm5hbWUiOiJFeGFtcGxlIHdpdGggc2VsZWN0aXZlIGRpc2Nsb3N1cmUifSwicmVzcG9uc2VfdXJpIjoiaHR0cDovLzEyNy4wLjAuMTo1NTc5Ni9hdXRoIn0.PHtlxQ3XoC-ohUfRlm7EHe700WI4qZnmrTFBnS0ohq7Q0rNZtMiNMPKamp3hk-E88HzppGbvppn_Z7zEh3fjmA";
        pub const AUTH_REQUEST_WITH_STATE_JWT: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4b3lwUGVKSHo1eGZkc2hWOU5xc1dUM0JVbUh2RFVEZThWeFdmNkxuMjNVaCN6RG5hZXhveXBQZUpIejV4ZmRzaFY5TnFzV1QzQlVtSHZEVURlOFZ4V2Y2TG4yM1VoIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6IjFkOGIwZDkzLTg2ZTgtNDEzNS04N2Q0LTUyNGJiMDUwMGJmMyIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiTm9ELTBmdGYxcWFUS0NNWjloWmVJdV9HZEhjdUZhM0hvUTgxLXBXZklQWSIsImNsaWVudF9tZXRhZGF0YSI6eyJzdWJqZWN0X3N5bnRheF90eXBlc19zdXBwb3J0ZWQiOlsiZGlkOmtleSJdfSwiY2xpZW50X2lkIjoiZGlkOmtleTp6RG5hZXhveXBQZUpIejV4ZmRzaFY5TnFzV1QzQlVtSHZEVURlOFZ4V2Y2TG4yM1VoIiwiY2xpZW50X2lkX3NjaGVtZSI6ImRpZCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzI3YWQxNzEtYzgwYS00ODViLWIwOTgtNTBkN2FkMjc4ZWY2IiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIn0sInByZWRpY2F0ZSI6bnVsbCwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm5hbWUiXSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYW4gaWRlbnRpdHkiLCJmb3JtYXQiOnsidmMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdfX19XX0sInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly8xMjcuMC4wLjE6NTU3OTYvYXV0aCJ9.j7OamoDYuCdMsTZ_dar7_KrZx7fufanTFWPB5LQk86UeAZ9yI_QHsGsmb1j9HkAnkVpgerShVJ3dO3HuxD-tPA";
        pub const AUTH_REQUEST: &str = r#"
            {
              "client_id": "did:key:zDnaehgaHKAP7LAA3Kwa4FjXjJ1G3BcaHqr5gfRySJcGDgBtV",
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
              "response_uri": "http://127.0.0.1:55796/auth"
            }
        "#;

        pub const AUTH_REQUEST_WITH_STATE: &str = r#"
            {
              "client_id": "did:key:zDnaex9UKhcwNpfrPva1HLj6DECNHhHkmuY6xszv1KGWksvfL",
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
              "response_uri": "http://127.0.0.1:55796/auth"
            }
        "#;

        pub fn presentation_definition() -> PresentationDefinition {
            serde_json::from_str(PRESENTATION_DEFINITION).unwrap()
        }

        pub fn presentation_submission() -> PresentationSubmission {
            serde_json::from_str(PRESENTATION_SUBMISSION).unwrap()
        }

        pub fn auth_request() -> ResolvedAuthRequest {
            serde_json::from_str(AUTH_REQUEST).unwrap()
        }

        pub fn auth_request_with_state() -> ResolvedAuthRequest {
            serde_json::from_str(AUTH_REQUEST_WITH_STATE).unwrap()
        }

        pub fn credential_data() -> Vec<CredTypeWithClaims> {
            vec![(
                "https://credentials.example.com/identity_credential",
                json!({"name": "John"}).try_into().unwrap(),
            )]
        }

        pub fn presentation_session() -> PresentationSession {
            PresentationSession {
                nonce: Nonce::from_secret(NONCE.to_owned()),
                presentation_definition: presentation_definition(),
                auth_request_jwt: Default::default(),
            }
        }

        pub fn presentation_test_case() -> PresentationTestCase {
            PresentationTestCase {
                request: auth_request(),
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                response_metadata: Default::default(),
                expected_credential_data: vec![(
                    "https://credentials.example.com/identity_credential",
                    json!({"name": "John"}).try_into().unwrap(),
                )],
            }
        }

        pub fn presentation_test_case_filter_by_path() -> PresentationTestCase {
            let cred1: CredTypeWithClaims = (
                "student_credential",
                json!({
                    "name": "Mike",
                    "email": {
                        "work": "work@mike.com",
                        "personal": "personal@mike.com"
                    }
                })
                .try_into()
                .unwrap(),
            );
            let cred2: CredTypeWithClaims = (
                "employee_credential",
                json!({
                    "name": "John",
                    "email": "john@example.com"
                })
                .try_into()
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred1.clone(), cred2];

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
            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                presentation_submission,
                response_metadata: Default::default(),
                expected_credential_data: vec![cred1],
            }
        }

        pub fn presentation_test_case_with_filter_by_cred_type() -> PresentationTestCase {
            let cred1: CredTypeWithClaims = (
                "student_credential",
                json!({
                    "name": "Mike",
                    "email": "mike@example.com",
                })
                .try_into()
                .unwrap(),
            );
            let cred2: CredTypeWithClaims = (
                "employee_credential",
                json!({
                    "name": "John",
                    "email": "john@example.com",
                })
                .try_into()
                .unwrap(),
            );
            let cred3: CredTypeWithClaims = (
                "employee_credential",
                json!({
                    "name": "Alex",
                    "email": "alex@example.com",
                })
                .try_into()
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred1.clone(), cred2, cred3];

            let constraints = r#"
            {
              "fields": [
                {
                  "path": [
                    "$.vct"
                  ],
                  "filter": {
                    "type": "string",
                    "const": "student_credential"
                  }
                }
              ]
            }
            "#;
            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                expected_credential_data: vec![cred1],
                presentation_submission,
                response_metadata: Default::default(),
            }
        }

        pub fn presentation_test_case_with_filter_by_cred_type_and_email() -> PresentationTestCase {
            let cred1: CredTypeWithClaims = (
                "student_credential",
                json!({
                    "name": "Mike",
                    "email": "mike@example.com",
                    "age": 20
                })
                .try_into()
                .unwrap(),
            );
            let cred2: CredTypeWithClaims = (
                "employee_credential",
                json!({
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35
                })
                .try_into()
                .unwrap(),
            );
            let cred3: CredTypeWithClaims = (
                "employee_credential",
                json!({
                    "name": "Alex",
                    "email": "alex@example.com",
                    "age": 26
                })
                .try_into()
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred1, cred2.clone(), cred3];

            let constraints = r#"
            {
              "fields": [
                {
                  "path": [
                    "$.vct"
                  ],
                  "filter": {
                    "type": "string",
                    "const": "employee_credential"
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
            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                expected_credential_data: vec![cred2],
                presentation_submission,
                response_metadata: Default::default(),
            }
        }

        pub fn presentation_test_case_with_optional_field() -> PresentationTestCase {
            let cred1: CredTypeWithClaims = (
                "student_credential",
                json!({
                    "name": "Mike",
                    "email": "mike@example.com",
                    "age": 20
                })
                .try_into()
                .unwrap(),
            );
            let cred2: CredTypeWithClaims = (
                "employee_credential_1",
                json!({
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer"
                })
                .try_into()
                .unwrap(),
            );
            let cred3: CredTypeWithClaims = (
                "employee_credential_2",
                json!({
                    "name": "Alex",
                    "email": "alex@example.com",
                    "age": 26

                })
                .try_into()
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred1, cred2, cred3.clone()];

            let constraints = r#"
            {
              "fields": [
                {
                  "path": [
                    "$.vct"
                  ],
                  "filter": {
                    "type": "string",
                    "const": "employee_credential_2"
                  }
                },
                {
                  "path": [
                    "$.position"
                  ],
                  "optional": true
                }
              ]
            }
            "#;
            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                expected_credential_data: vec![cred3],
                presentation_submission,
                response_metadata: Default::default(),
            }
        }

        pub fn presentation_test_case_with_constraints_for_particular_fields(
        ) -> PresentationTestCase {
            let cred1: CredTypeWithClaims = (
                "student_credential",
                json!({
                    "name": "Mike",
                    "email": "mike@example.com",
                    "age": 20
                })
                .try_into()
                .unwrap(),
            );
            let cred2: CredTypeWithClaims = (
                "employee_credential_1",
                json!({
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                    "address": {
                        "country": "UK",
                        "city": "London"
                    }
                })
                .try_into()
                .unwrap(),
            );
            let cred3: CredTypeWithClaims = (
                "employee_credential_2",
                json!({
                    "name": "Alex",
                    "email": "alex@example.com",
                    "age": 26,
                    "position": "senior engineer"

                })
                .try_into()
                .unwrap(),
            );
            let cred4: CredTypeWithClaims = (
                "employee_credential_3",
                json!({
                    "name": "Luis",
                    "email": "luis@example.com",
                    "age": 18,

                })
                .try_into()
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred1, cred2.clone(), cred3, cred4];

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
                    "$.position"
                  ],
                  "optional": false
                }
              ]
            }
            "#;

            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                expected_credential_data: vec![cred2],
                presentation_submission,
                response_metadata: Default::default(),
            }
        }
        pub fn presentation_test_case_with_constraints_with_patterns() -> PresentationTestCase {
            let cred: CredTypeWithClaims = (
                "employee_credential_1",
                json!({
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
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred.clone()];

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

            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                expected_credential_data: vec![cred],
                presentation_submission,
                response_metadata: Default::default(),
            }
        }
        pub fn presentation_test_case_with_constraints_with_invalid_value_for_pattern(
        ) -> PresentationTestCase {
            let cred: CredTypeWithClaims = (
                "employee_credential_1",
                json!({
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
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred.clone()];

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

            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                expected_credential_data: vec![cred],
                presentation_submission,
                response_metadata: Default::default(),
            }
        }
        pub fn presentation_test_case_with_constraints_with_invalid_value_for_const(
        ) -> PresentationTestCase {
            let cred: CredTypeWithClaims = (
                "employee_credential_1",
                json!({
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "Senior developer"

                })
                .try_into()
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred.clone()];

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

            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                expected_credential_data: vec![cred],
                presentation_submission,
                response_metadata: Default::default(),
            }
        }
        pub fn presentation_test_case_with_constraints_with_absent_required_claim(
        ) -> PresentationTestCase {
            let cred: CredTypeWithClaims = (
                "employee_credential_1",
                json!({
                    "name": "John",
                    "email": "john@example.com",
                    "age": 35,
                    "position": "lead engineer",
                })
                .try_into()
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> = vec![cred.clone()];

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

            let auth_request_str = PresentationTestCase::build_auth_request(constraints);
            let auth_request = serde_json::from_str(&auth_request_str).unwrap();

            let presentation_submission = serde_json::from_str(PRESENTATION_SUBMISSION).unwrap();

            PresentationTestCase {
                request: auth_request,
                credential_data,
                expected_credential_data: vec![cred],
                presentation_submission,
                response_metadata: Default::default(),
            }
        }

        pub fn presentation_test_case_with_state() -> PresentationTestCase {
            PresentationTestCase {
                request: auth_request_with_state(),
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                response_metadata: Default::default(),
                expected_credential_data: credential_data(),
            }
        }

        pub fn verification_test_case() -> VerificationTestCase {
            VerificationTestCase {
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                session: presentation_session(),
            }
        }
    }

    pub mod multi_presentation {
        use crate::nonce::Nonce;
        use crate::vc::oid4vp::tests::fixtures::NONCE;
        use crate::vc::oid4vp::tests::utils::{PresentationTestCase, VerificationTestCase};
        use crate::vc::oid4vp::tests::CredTypeWithClaims;
        use crate::vc::oid4vp::{
            AuthResponseOptions, PresentationSession, ResolvedAuthRequest, ResponseMode,
            ResponseType,
        };
        use crate::vc::presentation_exchange::{
            PresentationDefinition, PresentationSubmission, SubmissionRequirement,
            SubmissionRequirementBase, SubmissionRequirementObject, SubmissionRequirementPick,
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
                             "const":"SD_JWT_cred"
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
           "client_id":"did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX",
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
                                 "const":"SD_JWT_cred"
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
           "response_uri":"http://127.0.0.1:55796/auth"
        }"#;

        const AUTH_REQUEST_WITH_STATE: &str = r#"
        {
           "client_id":"did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX",
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
                                 "const":"SD_JWT_cred"
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
           "response_uri":"http://127.0.0.1:55796/auth"
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

        pub fn credential_data() -> Vec<CredTypeWithClaims> {
            vec![
                (
                    "https://credentials.example.com/identity_credential",
                    json!({
                        "name": "John",
                        "surname": "Doe",
                        "date": "09/09/1989",
                    })
                    .try_into()
                    .unwrap(),
                ),
                (
                    "SD_JWT_cred",
                    json!({
                        "name": "John",
                        "email": {
                            "work": "work@example.com",
                            "personal": "personal@example.com"
                        },
                    })
                    .try_into()
                    .unwrap(),
                ),
            ]
        }

        pub fn presentation_session() -> PresentationSession {
            PresentationSession {
                nonce: Nonce::from_secret(NONCE.to_owned()),
                presentation_definition: presentation_definition(),
                auth_request_jwt: Default::default(),
            }
        }

        pub fn presentation_test_case() -> PresentationTestCase {
            PresentationTestCase {
                request: auth_request(),
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                response_metadata: Default::default(),
                expected_credential_data: credential_data(),
            }
        }

        pub fn presentation_test_case_filter_by_path() -> PresentationTestCase {
            let cred1: CredTypeWithClaims = (
                "cred_1",
                json!({
                    "name": "Mike",
                    "age": 20,
                    "address": {
                        "country": "UK",
                        "city": "London"
                    }
                })
                .try_into()
                .unwrap(),
            );
            let cred2: CredTypeWithClaims = (
                "cred_2",
                json!({
                    "name": "John",
                    "email": "john@example.com"
                })
                .try_into()
                .unwrap(),
            );
            let cred3: CredTypeWithClaims = (
                "cred_3",
                json!({
                    "email": "alex@example.com",
                    "age": 35
                })
                .try_into()
                .unwrap(),
            );
            let credential_data: Vec<CredTypeWithClaims> =
                vec![cred1.clone(), cred2, cred3.clone()];
            let auth_request_str = r#"
            {
               "client_id":"did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX",
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
               "response_uri":"http://127.0.0.1:55796/auth"
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
                request: auth_request,
                expected_credential_data: vec![cred1, cred3],
                credential_data,
                presentation_submission,
                response_metadata: Default::default(),
            }
        }

        pub fn presentation_test_case_with_state() -> PresentationTestCase {
            PresentationTestCase {
                request: auth_request_with_state(),
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                response_metadata: Default::default(),
                expected_credential_data: credential_data(),
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
    }
}

pub mod utils {
    use crate::did::didkey::DIDKey;
    use crate::http::{HttpClient, MockHttpClient};
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::inmem::nonce::LocalNonceGenerator;
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
    use crate::vc::claims::{Claim, Claims};
    use crate::vc::core::api::PresentationRestrictionValue;
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::sd_jwt_vc;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VPMetadata};
    use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
    use crate::vc::oid4vp::holder::HolderService;
    use crate::vc::oid4vp::signer::Signer;
    use crate::vc::oid4vp::tests::fixtures::{CREDENTIAL_ID, VERIFIER_URL};
    use crate::vc::oid4vp::tests::CredTypeWithClaims;
    use crate::vc::oid4vp::verifier::VerifierService;
    use crate::vc::oid4vp::{
        AuthorizationResponse, AuthorizationResponseMetadata, ClientMetadata, CredentialMapping,
        Holder, PresentationSession, ResolvedAuthRequest, ResponseType, Verifier,
    };
    use crate::vc::presentation_exchange::PresentationSubmission;
    use crate::vc::{presentation_exchange, Credential, VCFormatsAPI, VCMetadata};
    use async_trait::async_trait;
    use oauth2::http::{Method, Request, Response, StatusCode};
    use openid4vp::core::metadata::parameters::SubjectSyntaxTypesSupported;
    use openid4vp::core::object::UntypedObject;
    use openid4vp::core::response::parameters::IdToken;
    use openid4vp::core::response::PostRedirection;
    use openid4vp::core::util::http::AsyncHttpClient;
    use openid4vp::wallet::{IdTokenParams, Wallet};
    use sd_jwt_rs::utils::decode_sd_jwt;
    use sd_jwt_rs::SDJWTSerializationFormat;
    use serde_json::{json, Value};
    use ssi::dids::DIDURLBuf;
    use std::collections::HashMap;
    use std::str::FromStr;
    use url::Url;

    pub struct PresentationTestCase {
        pub request: ResolvedAuthRequest,
        pub credential_data: Vec<CredTypeWithClaims>,
        pub presentation_submission: PresentationSubmission,
        pub response_metadata: AuthorizationResponseMetadata,
        pub expected_credential_data: Vec<CredTypeWithClaims>,
    }

    impl PresentationTestCase {
        pub fn mock_http_auth_response_endpoint(
            &self,
            http_client: &mut MockHttpClient,
            claims_to_exclude: Option<&HashMap<String, Vec<String>>>,
        ) {
            let expected_credential_data = self.expected_credential_data.clone();
            let expected_presentation_submission = self.presentation_submission.clone();
            let client_id = self.request.client_id.to_owned();
            let nonce = self.request.nonce.clone();
            let response_type = self.request.response_type.clone();
            let state = self.request.state.clone();

            mock_http_req_async_predicate(
                http_client,
                Method::POST,
                build_url(VERIFIER_URL, "auth"),
                move |request| {
                    Self::mock_http_auth_response_endpoint_helper(
                        expected_credential_data.clone(),
                        expected_presentation_submission.clone(),
                        client_id.clone(),
                        nonce.clone(),
                        response_type.clone(),
                        request,
                        state.clone(),
                    )
                },
                PostRedirection {
                    redirect_uri: build_url(VERIFIER_URL, "redirect"),
                },
                StatusCode::OK,
                1.into(),
            );
        }

        async fn mock_http_auth_response_endpoint_helper(
            expected_credential_data: Vec<CredTypeWithClaims>,
            expected_presentation_submission: PresentationSubmission,
            client_id: String,
            nonce: Nonce,
            response_type: ResponseType,
            request: String,
            expected_state: Option<String>,
        ) -> bool {
            let form = serde_urlencoded::from_bytes(request.as_bytes()).unwrap();
            let claims = Self::extract_claims(&form);
            for index in 0..claims.len() {
                validate_claims(
                    claims.get(index).unwrap(),
                    expected_credential_data.get(index).unwrap(),
                )
            }

            let mut presentation_submission: PresentationSubmission =
                serde_json::from_str(&form["presentation_submission"]).unwrap();
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
                assert_eq!(id_token.audience, client_id)
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
            for (vct, claims) in &self.credential_data {
                let credential =
                    Credential::SdJwt(create_sd_jwt_vc(vct, claims, &holder_key_handle).await);
                let metadata = DefaultMetadataProcessor::resolve_metadata(
                    &credential,
                    KeyMetadata {
                        did_url: "did:fake:test".to_string(),
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

        pub async fn build_credential_mapping(
            &self,
            holder_key: (KeyID, KeyHandle),
        ) -> CredentialMapping {
            let (kid, key_handle) = holder_key;
            let inputs =
                presentation_exchange::split_to_inputs(&self.request.presentation_definition, None)
                    .unwrap();

            let mut result = CredentialMapping::new();

            for input in inputs {
                let (vct, claims) = self
                    .credential_data
                    .iter()
                    .find(|(vct, _)| {
                        input.restrictions.iter().any(|restriction| {
                            matches!(restriction.value.as_ref(), Some(PresentationRestrictionValue::Const(value)) if value == &vct.to_string())
                        })
                    })
                    .unwrap();

                let sd_jwt_vc = create_sd_jwt_vc(vct, claims, &key_handle).await;

                result.insert(
                    input.id,
                    vec![CredentialEntry {
                        credential: Credential::SdJwt(sd_jwt_vc),
                        kid: kid.to_string(),
                        id: CREDENTIAL_ID.to_string(),
                    }],
                );
            }

            result
        }

        pub fn extract_claims(form: &HashMap<String, String>) -> Vec<Claims> {
            let vp_token = form.get("vp_token").unwrap();
            let vp_token_value: serde_json::Value =
                serde_json::from_str(vp_token).unwrap_or(serde_json::to_value(vp_token).unwrap());

            match vp_token_value {
                serde_json::Value::String(token) => {
                    vec![decode_sd_jwt(token, SDJWTSerializationFormat::Compact)
                        .unwrap()
                        .try_into()
                        .unwrap()]
                }
                serde_json::Value::Array(tokens) => tokens
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

        pub fn build_auth_request(constraints: &str) -> String {
            format!(
                r#"{{
              "client_id": "did:key:zDnaehgaHKAP7LAA3Kwa4FjXjJ1G3BcaHqr5gfRySJcGDgBtV",
              "state": null,
              "presentation_definition": {{
                "id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                "input_descriptors": [
                  {{
                    "id": "Identity-1",
                    "name": "Identity VC",
                    "purpose": "We want an identity",
                    "format": {{
                      "dc+sd-jwt": {{
                        "sd-jwt_alg_values": [
                          "ES256",
                          "EdDSA"
                        ],
                        "kb-jwt_alg_values": [
                          "ES256",
                          "EdDSA"
                        ]
                      }}
                    }},
                    "constraints": {constraints}
                  }}
                ]
              }},
              "nonce": "nonce",
              "response_mode": "direct_post",
              "response_type": "vp_token",
              "response_uri": "http://127.0.0.1:55796/auth"
            }}"#
            )
        }
    }

    pub struct VerificationTestCase {
        pub credential_data: Vec<CredTypeWithClaims>,
        pub presentation_submission: PresentationSubmission,
        pub session: PresentationSession,
    }

    impl VerificationTestCase {
        pub async fn vp_token(&self, nonce: &Nonce, verifier_id: &str) -> serde_json::Value {
            let kms = LocalKms::new();
            let (_, holder_key_handle) = kms
                .create_and_handle(KeyType::P256, CreateOptions::default())
                .await
                .unwrap();

            let mut presentations: Vec<sd_jwt_vc::Presentation> = vec![];
            for (vct, claims) in self.credential_data.iter() {
                let vc = create_sd_jwt_vc(vct, claims, &holder_key_handle).await;
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

        pub async fn auth_response(
            &self,
            nonce: &Nonce,
            verifier_id: &str,
        ) -> AuthorizationResponse {
            AuthorizationResponse {
                vp_token: self.vp_token(nonce, verifier_id).await,
                presentation_submission: self.presentation_submission.clone(),
                id_token: None,
                state: None,
            }
        }

        pub async fn auth_response_with_id_token(
            &self,
            nonce: &Nonce,
            verifier_id: &str,
            id_token_params: IdTokenParams,
        ) -> AuthorizationResponse {
            let mut auth_resp = self.auth_response(nonce, verifier_id).await;
            auth_resp.id_token = Some(generate_did_based_id_token(id_token_params).await);

            auth_resp
        }
    }

    pub async fn holder_service(
        http_client: impl HttpClient,
        kms: LocalKms,
        vault: InMemVault,
    ) -> impl Holder {
        let inner = vc::core::HolderService::new(
            kms.clone(),
            vault,
            vc::core::HolderMetadata {
                client_id: "client_id".to_string(),
            },
        );

        HolderService::new(inner, http_client, kms, None)
    }

    async fn create_verifier_service(invalid_key_id: bool) -> (impl Verifier, String) {
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceGenerator::default();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let mut key_metadata = key_metadata;

        if invalid_key_id {
            key_metadata.kid = "invalid_key_id".to_string();
        }

        let inner = vc::core::VerifierService::new(&did);
        let sub_syntax_types = SubjectSyntaxTypesSupported(vec!["did:key".to_string()]);

        let mut client_metadata =
            ClientMetadata::try_from(Value::from(UntypedObject::default())).unwrap();
        client_metadata.0.insert(sub_syntax_types);

        let verifier = VerifierService::new(
            inner,
            kms,
            nonce_gen,
            MockHttpClient::new(),
            did.clone(),
            key_metadata,
            Some(client_metadata),
        );

        (verifier, did)
    }

    pub async fn verifier_service() -> (impl Verifier, String) {
        create_verifier_service(false).await
    }

    pub async fn verifier_service_with_invalid_kid() -> (impl Verifier, String) {
        create_verifier_service(true).await
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
            vc::core::VerifierService::new(&did),
            kms_mock,
            LocalNonceGenerator::default(),
            MockHttpClient::new(),
            did.clone(),
            key_metadata,
            None,
        );

        (verifier, did)
    }

    pub fn build_url(base_url: &str, url_part: &str) -> Url {
        Url::parse(base_url).unwrap().join(url_part).unwrap()
    }

    pub async fn create_sd_jwt_vc(
        vct: &str,
        claims: &Claims,
        holder_key_handle: &KeyHandle,
    ) -> sd_jwt_vc::Credential {
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

        SdJwtAPI::create_vc(
            claims.clone(),
            (&issuer_did_url, issuer_key_handle),
            (&holder_did_url, holder_key_handle.clone()),
            VCMetadata {
                vct: vct.to_owned(),
                lifetime: time::Duration::days(365),
                disclosures,
                credential_status: None,
            },
        )
        .await
        .unwrap()
    }

    pub async fn create_sd_jwt_vp(
        vc: &sd_jwt_vc::Credential,
        disclosures: serde_json::Value,
        nonce: &Nonce,
        verifier_id: &str,
        holder_key_handle: &KeyHandle,
    ) -> sd_jwt_vc::Presentation {
        SdJwtAPI::create_vp(
            vc,
            holder_key_handle.clone(),
            nonce,
            verifier_id,
            VPMetadata {
                disclosures: disclosures.as_object().unwrap().to_owned(),
            },
        )
        .await
        .unwrap()
    }

    pub fn validate_claims(claims: &Claims, credential_data: &CredTypeWithClaims) {
        let (vct, expected_claims) = credential_data;
        assert_eq!(claims.get("vct").unwrap(), &Claim::String(vct.to_string()));

        for (key, value) in expected_claims.claims() {
            assert_eq!(
                claims.get(key).unwrap(),
                value,
                "Claims: expected {key}: {value}"
            );
        }
    }

    pub async fn generate_did_based_id_token(params: IdTokenParams) -> String {
        let kms = LocalKms::new();
        let inner = vc::core::HolderService::new(
            kms.clone(),
            InMemVault::new(),
            vc::core::HolderMetadata {
                client_id: "client_id".to_string(),
            },
        );

        let holder = HolderService::new(inner, MockHttpClient::new(), kms.clone(), None);
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
}
