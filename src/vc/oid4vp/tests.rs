use crate::vc::Claims;

type CredTypeWithClaims = (&'static str, Claims);

pub mod fixtures {
    pub const VERIFIER_URL: &str = "http://127.0.0.1:55796";
    pub const NONCE: &str = "n0NcE";
    pub const CLIENT_ID: &str = "wallet-dev";
    pub const REQUEST_URI: &str = "openid4vp://?client_id=did%3Akey%3AzDnaex9UKhcwNpfrPva1HLj6DECNHhHkmuY6xszv1KGWksvfL&request_uri=http%3A%2F%2F127.0.0.1%3A55796%2Frequest";

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
                    "vc+sd-jwt":{
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
                    "format": "vc+sd-jwt",
                    "path": "$"
                }
            ]
        }"#;

        pub const AUTH_REQUEST_JWT: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4OVVLaGN3TnBmclB2YTFITGo2REVDTkhoSGttdVk2eHN6djFLR1drc3ZmTCN6RG5hZXg5VUtoY3dOcGZyUHZhMUhMajZERUNOSGhIa211WTZ4c3p2MUtHV2tzdmZMIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6IlhVY2ZUTmZKLWQ1cG05OVhVS0c3bUdLdWt3WGVEYXNhUmxnaEtFcEd4aDAiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0cyI6eyJ2YytzZC1qd3QiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiXX19fSwiY2xpZW50X2lkIjoiZGlkOmtleTp6RG5hZXg5VUtoY3dOcGZyUHZhMUhMajZERUNOSGhIa211WTZ4c3p2MUtHV2tzdmZMIiwiY2xpZW50X2lkX3NjaGVtZSI6ImRpZCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzI3YWQxNzEtYzgwYS00ODViLWIwOTgtNTBkN2FkMjc4ZWY2IiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLm5hbWUiXSwicHJlZGljYXRlIjpudWxsLCJvcHRpb25hbCI6dHJ1ZSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLnZjdCJdLCJwcmVkaWNhdGUiOm51bGwsImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX0sIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7InZjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl0sImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXX19fV0sIm5hbWUiOiJFeGFtcGxlIHdpdGggc2VsZWN0aXZlIGRpc2Nsb3N1cmUifSwicmVzcG9uc2VfdXJpIjoiaHR0cDovLzEyNy4wLjAuMTo1NTc5Ni9hdXRoIn0.E5Y-Vk_ncPljaRr562qVkFRhAxYIBw_2BoajKJc8Wm-y8qQb2CcmKaHURoWxc6IG3ky7AWLs1ubI28WWak5WJA";
        pub const AUTH_REQUEST: &str = r#"
            {
              "client_id": "did:key:zDnaex9UKhcwNpfrPva1HLj6DECNHhHkmuY6xszv1KGWksvfL",
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

        pub fn credential_data() -> Vec<CredTypeWithClaims> {
            vec![(
                "https://credentials.example.com/identity_credential",
                json!({"name": "John"}),
            )]
        }

        pub fn presentation_session() -> PresentationSession {
            PresentationSession {
                nonce: Nonce(NONCE.to_owned()),
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
                    "vc+sd-jwt":{
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
                    "vc+sd-jwt":{
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
                    "format": "vc+sd-jwt",
                    "path": "$[0]"
                },
                {
                    "id": "SD_JWT_cred",
                    "format": "vc+sd-jwt",
                    "path": "$[1]"
                }
            ]
        }"#;

        const AUTH_REQUEST: &str = r#"
        {
           "client_id":"did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX",
           "presentation_definition": {
               "id":"327ad171-c80a-485b-b098-50d7ad278ef6",
               "input_descriptors":[
                  {
                     "id":"Identity-1",
                     "name":"Identity VC",
                     "purpose":"We want an identity",
                     "format":{
                        "vc+sd-jwt":{
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
                        "vc+sd-jwt":{
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

        pub fn credential_data() -> Vec<CredTypeWithClaims> {
            vec![
                (
                    "https://credentials.example.com/identity_credential",
                    json!({
                        "name": "John",
                        "surname": "Doe",
                        "date": "09/09/1989",
                    }),
                ),
                (
                    "SD_JWT_cred",
                    json!({
                        "name": "John",
                        "email": {
                            "work": "work@example.com",
                            "personal": "personal@example.com"
                        },
                    }),
                ),
            ]
        }

        pub fn presentation_session() -> PresentationSession {
            PresentationSession {
                nonce: Nonce(NONCE.to_owned()),
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
            }
        }

        pub fn verification_test_case() -> VerificationTestCase {
            VerificationTestCase {
                credential_data: credential_data(),
                presentation_submission: presentation_submission(),
                session: presentation_session(),
            }
        }

        pub fn auth_response_options(submission_uri: Url) -> AuthResponseOptions {
            AuthResponseOptions {
                type_: ResponseType::VpToken,
                mode: ResponseMode::DirectPost,
                submission_uri,
            }
        }
    }
}

pub mod utils {
    use crate::crypto::Alg;
    use crate::did::didkey::DIDKey;
    use crate::did::universal::UniversalResolver;
    use crate::http::{HttpClient, MockHttpClient};
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::inmem::nonce::LocalNonceGenerator;
    use crate::inmem::vault::InMemVault;
    use crate::kms::{CreateOptions, KeyID, KeyType, Kms};
    use crate::nonce::Nonce;
    use crate::utils::http::test::mock_http_req_async_predicate;
    use crate::utils::test_utils;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vault::{CredentialEntry, Vault};
    use crate::vc;
    use crate::vc::formats::sd_jwt_vc;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VPMetadata};
    use crate::vc::oid4vp::holder::HolderService;
    use crate::vc::oid4vp::tests::fixtures::VERIFIER_URL;
    use crate::vc::oid4vp::tests::CredTypeWithClaims;
    use crate::vc::oid4vp::verifier::VerifierService;
    use crate::vc::oid4vp::{
        AuthorizationResponse, AuthorizationResponseMetadata, ClientMetadata, CredentialMapping,
        Holder, PresentationSession, ResolvedAuthRequest, Verifier,
    };
    use crate::vc::presentation_exchange::PresentationSubmission;
    use crate::vc::{
        presentation_exchange, Claims, Credential, CredentialMetadata, VCFormat, VCFormatsAPI,
        VCMetadata,
    };
    use oauth2::http::{Method, StatusCode};
    use oid4vp::core::authorization_request::parameters::ResponseType;
    use oid4vp::core::metadata::parameters::SubjectSyntaxTypesSupported;
    use oid4vp::core::object::UntypedObject;
    use oid4vp::core::response::parameters::IdToken;
    use oid4vp::core::response::PostRedirection;
    use sd_jwt_rs::utils::decode_sd_jwt;
    use sd_jwt_rs::SDJWTSerializationFormat;
    use serde_json::{json, Value};
    use ssi::did::DIDURL;
    use std::collections::HashMap;
    use std::str::FromStr;
    use url::Url;

    pub struct PresentationTestCase {
        pub request: ResolvedAuthRequest,
        pub credential_data: Vec<CredTypeWithClaims>,
        pub presentation_submission: PresentationSubmission,
        pub response_metadata: AuthorizationResponseMetadata,
    }

    impl PresentationTestCase {
        pub fn mock_http_auth_response_endpoint(
            &self,
            http_client: &mut MockHttpClient,
            claims_to_exclude: Option<&HashMap<String, Vec<String>>>,
        ) {
            let credential_data = self.credential_data.clone();
            let expected_presentation_submission = self.presentation_submission.clone();
            let client_id = self.request.client_id.to_owned();
            let nonce = self.request.nonce.clone();
            let response_type = self.request.response_type.clone();

            mock_http_req_async_predicate(
                http_client,
                Method::POST,
                build_url(VERIFIER_URL, "auth"),
                move |request| {
                    Self::mock_http_auth_response_endpoint_helper(
                        credential_data.clone(),
                        expected_presentation_submission.clone(),
                        client_id.clone(),
                        nonce.clone(),
                        response_type.clone(),
                        request,
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
            credential_data: Vec<CredTypeWithClaims>,
            expected_presentation_submission: PresentationSubmission,
            client_id: String,
            nonce: Nonce,
            response_type: ResponseType,
            request: String,
        ) -> bool {
            let form = serde_urlencoded::from_bytes(request.as_bytes()).unwrap();
            let claims = Self::extract_claims(&form);
            for index in 0..claims.len() {
                validate_claims(
                    claims.get(index).unwrap(),
                    credential_data.get(index).unwrap(),
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

                assert_eq!(id_token.nonce, nonce.0);
                assert_eq!(id_token.audience, client_id)
            }

            true
        }
        pub async fn prepare_vault(&self, kms: &LocalKms, with_extra_creds: bool) -> InMemVault {
            let vault = InMemVault::new();

            // Save credentials
            let holder_key = kms
                .create_and_handle(KeyType::P256, CreateOptions {})
                .await
                .unwrap();
            self.store_creds(&vault, holder_key).await;

            if with_extra_creds {
                // Save extra credentials using another holder key
                let another_holder_key = kms
                    .create_and_handle(KeyType::P256, CreateOptions {})
                    .await
                    .unwrap();
                self.store_creds(&vault, another_holder_key).await;
            }

            vault
        }

        pub async fn store_creds(&self, vault: &InMemVault, holder_key: (KeyID, KeyHandle)) {
            let (holder_kid, holder_key_handle) = holder_key;
            for (vct, claims) in &self.credential_data {
                let sd_jwt_vc = create_sd_jwt_vc(vct, claims, &holder_key_handle).await;

                let res = vault
                    .store_credential(
                        Credential::SdJwt(sd_jwt_vc),
                        &CredentialMetadata {
                            type_: vct.to_string(),
                            format: VCFormat::SdJwtVc,
                            kid: holder_kid.to_owned(),
                            alg: Some(Alg::ES256),
                            tags: vec![],
                        },
                    )
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
                    .find(|(vct, _)| *vct == input.type_)
                    .unwrap();

                let sd_jwt_vc = create_sd_jwt_vc(vct, claims, &key_handle).await;

                result.insert(
                    input.id,
                    vec![CredentialEntry {
                        credential: Credential::SdJwt(sd_jwt_vc),
                        kid: kid.to_string(),
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
                    vec![decode_sd_jwt(token, SDJWTSerializationFormat::Compact).unwrap()]
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
                    .collect(),
                _ => panic!("Invalid VP token format: {:?}", vp_token_value),
            }
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
                .create_and_handle(KeyType::P256, CreateOptions {})
                .await
                .unwrap();

            let mut presentations: Vec<sd_jwt_vc::Presentation> = vec![];
            for (vct, claims) in self.credential_data.iter() {
                let vc = create_sd_jwt_vc(vct, claims, &holder_key_handle).await;
                let vp =
                    create_sd_jwt_vp(&vc, claims.clone(), nonce, verifier_id, &holder_key_handle)
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
            }
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

        HolderService::new(inner, UniversalResolver::new(), http_client, kms, None)
    }

    pub async fn verifier_service() -> (impl Verifier, String) {
        let kms = LocalKms::new();
        let nonce_gen = LocalNonceGenerator::default();
        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;
        let inner = vc::core::VerifierService::new(&did);
        let sub_syntax_types = SubjectSyntaxTypesSupported(vec!["did:key".to_string()]);

        let mut client_metadata =
            ClientMetadata::try_from(Value::from(UntypedObject::default())).unwrap();
        client_metadata.0.insert(sub_syntax_types);

        let verifier = VerifierService::new(
            inner,
            kms,
            UniversalResolver::new(),
            nonce_gen,
            did.clone(),
            key_metadata,
            Some(client_metadata),
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

        let did = DIDKey::new().generate(holder_key_handle.clone()).unwrap();
        let holder_did_url = DIDURL::from_str(&did).unwrap();

        let disclosures: Vec<String> = claims
            .as_object()
            .unwrap()
            .keys()
            .map(|key| format!("$.{}", key))
            .collect();

        SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(claims).unwrap(),
            (&issuer_did_url, issuer_key_handle),
            (&holder_did_url, holder_key_handle.clone()),
            VCMetadata {
                vct: vct.to_owned(),
                lifetime: time::Duration::days(365),
                disclosures,
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

        assert_eq!(&claims["vct"], vct);

        for (key, value) in expected_claims.as_object().unwrap() {
            assert_eq!(
                &claims[key], value,
                "Claims: {claims}, expected {key}: {value}"
            );
        }
    }
}
