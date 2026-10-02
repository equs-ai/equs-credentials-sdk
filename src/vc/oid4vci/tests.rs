pub mod fixtures {
    use crate::nonce::{Nonce, NonceHandler};
    use crate::vc::claims::Claims;
    use crate::vc::oid4vci::metadata::IssuerMetadata;
    use crate::vc::oid4vci::{
        AuthorizationCodeGrant, AuthorizationMetadata, CredDefMetadata, CredentialOfferGrants,
        CredentialOfferParams, CredentialRequest, CredentialResponse, PreAuthorizedCode,
        PreAuthorizedCodeGrant,
    };
    use async_trait::async_trait;
    use oauth2::AccessToken;
    use oid4vci::types::{CredentialConfigurationId, IssuerUrl};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use test_fixtures::access_token::AccessToken as AccessTokenFixture;
    use test_fixtures::equs_sdk::inmem::kms::LocalKms as FixtureKms;
    use test_fixtures::keys::FixtureKey;
    use test_fixtures::pop::ProofOfPossession as FixtureProofOfPossession;
    use test_fixtures::sd_jwt_vc::SdJwtVc;

    pub const ISSUER_URL: &str = "https://issuer-backend.com";
    pub const AUTH_URL: &str = "https://authz-backend.com";
    pub const TOKEN_INTROSPECT_URL: &str =
        "https://authz-backend.com/protocol/openid-connect/token/introspect";
    pub const JWKS_URL: &str = "http://issuer.org/certs";
    pub const NONCE: &str = "KB50VOm9I-kPLT9mAACV8g";

    /// Signs a bearer access token; `scope` sets the `scope` claim, or omits it
    /// entirely when `None` — the shape the scope-rejection tests take.
    pub async fn access_token(scope: Option<&str>) -> String {
        let kms = FixtureKms::new();
        let key = FixtureKey::create_default(&kms).await.expect("fixture key");
        let builder =
            AccessTokenFixture::builder(&key).issuer("https://idp.example/realms/pid-issuer-realm");
        let builder = match scope {
            Some(scope) => builder.scope(scope),
            None => builder.without_scope(),
        };
        builder.build().await.expect("access token")
    }

    /// Issues an SD-JWT VC over the claims the OID4VCI fixtures previously
    /// hard-coded: `given_name`, `family_name` and `dob`.
    pub async fn sd_jwt_creds() -> String {
        let kms = FixtureKms::new();
        let issuer = FixtureKey::create_default(&kms).await.expect("issuer key");
        let holder = FixtureKey::create_default(&kms).await.expect("holder key");
        SdJwtVc::builder(&issuer, &holder)
            .vct("SD_JWT_cred")
            .claim("given_name", "John".into())
            .claim("family_name", "Doe".into())
            .claim("dob", "09/09/1989".into())
            .build()
            .await
            .expect("sd-jwt credential")
    }

    pub const NOTIFICATION_ID: &str = "8fcc7362-dc77-4aaf-a953-fa56e39b22f7";
    pub const SCOPE: &str = "SD_JWT_cred";
    pub const CRED_DEF_ID: &str = "SD_JWT_cred_sample";
    pub const REQ_URI_CODE: &str = "fake_request_uri";
    pub const AUTH_REDIRECT_URL: &str = "urn:ietf:wg:oauth:2.0:oob";

    #[derive(Default)]
    pub struct MockNonceHandler {}

    #[async_trait]
    impl NonceHandler for MockNonceHandler {
        async fn generate(&self) -> crate::nonce::Result<Nonce> {
            Ok(Nonce::from_secret(NONCE.to_string()))
        }

        async fn validate(&self, nonce: &Nonce) -> crate::nonce::Result<bool> {
            Ok(true)
        }

        async fn invalidate(&self, nonces: &[Nonce]) -> crate::nonce::Result<()> {
            Ok(())
        }
    }

    pub struct SampleIssuerMetadata {}
    impl SampleIssuerMetadata {
        fn with_sdjwtvc_conf_json() -> serde_json::Value {
            json!(
                {
                    "credential_issuer": ISSUER_URL,
                    "authorization_servers": [AUTH_URL],
                    "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                    "nonce_endpoint": ISSUER_URL.to_owned()+"/nonce",
                    "batch_credential_issuance": {
                        "batch_size": 3
                    },
                    "deferred_credential_endpoint": ISSUER_URL.to_owned()+"/deferred_credential",
                    "notification_endpoint": ISSUER_URL.to_owned()+"/notification",
                    "credential_configurations_supported": {
                        CRED_DEF_ID: {
                            "format": "dc+sd-jwt",
                            "scope": "SD_JWT_cred",
                            "cryptographic_binding_methods_supported": [
                                "jwk"
                            ],
                            "credential_signing_alg_values_supported": [
                                "ES256"
                            ],
                            "proof_types_supported": {
                                "jwt": {
                                    "proof_signing_alg_values_supported": [
                                        "ES256"
                                    ],
                                },
                            },
                            "vct": "SD_JWT_cred",
                            "credential_metadata": {
                                "claims": [
                                    { "path": ["given_name"] },
                                    { "path": ["family_name"] },
                                    { "path": ["dob"] },
                                ],
                            },
                        },
                    },
                }
            )
        }

        pub fn with_sdjwtvc_conf() -> IssuerMetadata {
            let metadata = serde_json::from_value(SampleIssuerMetadata::with_sdjwtvc_conf_json());
            metadata.unwrap()
        }

        pub fn with_sdjwtvc_no_deferred_endpoint_conf() -> IssuerMetadata {
            let mut metadata = SampleIssuerMetadata::with_sdjwtvc_conf_json();
            metadata
                .as_object_mut()
                .unwrap()
                .remove("deferred_credential_endpoint");
            serde_json::from_value::<IssuerMetadata>(metadata).unwrap()
        }

        pub fn with_sdjwtvc_no_notification_endpoint_conf() -> IssuerMetadata {
            let mut metadata = SampleIssuerMetadata::with_sdjwtvc_conf_json();
            metadata
                .as_object_mut()
                .unwrap()
                .remove("notification_endpoint");
            serde_json::from_value::<IssuerMetadata>(metadata).unwrap()
        }

        pub fn with_jwtvc_conf() -> IssuerMetadata {
            let metadata = serde_json::from_value(json!(
                {
                    "credential_issuer": ISSUER_URL,
                    "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                    "nonce_endpoint": ISSUER_URL.to_owned()+"/nonce",
                    "credential_configurations_supported": {
                        SCOPE: {
                            "format": "jwt_vc_json",
                            "credential_definition": {
                                "type": [],
                            },
                        },
                    },
                }
            ));
            metadata.unwrap()
        }

        pub fn with_jwtldvc_conf() -> IssuerMetadata {
            let metadata = serde_json::from_value(json!(
                {
                    "credential_issuer": ISSUER_URL,
                    "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                    "nonce_endpoint": ISSUER_URL.to_owned()+"/nonce",
                    "credential_configurations_supported": {
                        SCOPE: {
                            "format": "jwt_vc_json-ld",
                            "credential_definition": {
                                "@context": [],
                                "type": [],
                            },
                        },
                    },
                }
            ));
            metadata.unwrap()
        }

        pub fn with_custom_issuer_metadata_for_ldp_vc() -> IssuerMetadata {
            serde_json::from_value(json!({
                "credential_issuer": ISSUER_URL,
                "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                "nonce_endpoint": ISSUER_URL.to_owned()+"/nonce",
                "credential_configurations_supported": {
                    "LdpVc": {
                        "format": "ldp_vc",
                        "scope": "SD_JWT_cred",
                        "@context": [
                            "https://www.w3.org/ns/credentials/v2",
                            "https://www.w3.org/ns/credentials/examples/v2"
                        ],
                        "type": [
                            "VerifiableCredential",
                        ],
                        "cryptographic_binding_methods_supported": [
                            "jwk"
                        ],
                        "credential_signing_alg_values_supported": [
                            "EcdsaRdfc2019",
                            "EdDsaRdfc2022"
                        ],
                        "credential_definition": {
                            "@context": [
                                "https://www.w3.org/ns/credentials/v2",
                                "https://www.w3.org/ns/credentials/examples/v2"
                            ],
                            "type": [
                                "VerifiableCredential",
                            ],
                        },
                        "credential_metadata": {
                            "claims": [
                                { "path": ["credentialSubject", "vct"] },
                                { "path": ["credentialSubject", "given_name"] },
                                { "path": ["credentialSubject", "family_name"] },
                                { "path": ["credentialSubject", "dob"] },
                            ],
                            "display": [
                                {
                                    "name": "University Credential",
                                    "locale": "en-US",
                                    "logo": {
                                        "uri": "https://exampleuniversity.com/public/logo.png",
                                        "alt_text": "a square logo of a university"
                                    },
                                    "background_color": "#12107c",
                                    "background_image": {
                                        "uri": "https://university.example.edu/public/background-image.png"
                                    },
                                    "text_color": "#FFFFFF"
                                }
                            ]
                        }
                    }
                },
            }))
            .unwrap()
        }
        pub fn with_isomdl_conf() -> IssuerMetadata {
            let metadata = serde_json::from_value(json!(
                {
                    "credential_issuer": ISSUER_URL,
                    "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                    "credential_configurations_supported": {
                        SCOPE: {
                            "format": "mso_mdoc",
                            "doctype": "",
                        },
                    },
                }
            ));
            metadata.unwrap()
        }
    }

    pub fn sample_authorization_metadata() -> AuthorizationMetadata {
        let metadata = serde_json::from_value(json!(
            {
                "issuer": AUTH_URL,
                "authorization_endpoint": AUTH_URL.to_owned()+"/auth",
                "token_endpoint": AUTH_URL.to_owned()+"/token",
                "introspection_endpoint": TOKEN_INTROSPECT_URL,
                "jwks_uri": AUTH_URL.to_owned()+"/cert",
                "grant_types_supported": [
                    "authorization_code",
                ],
                "response_types_supported": [
                    "code",
                    "token",
                ],
                "subject_types_supported": [
                    "public",
                ],
                "id_token_signing_alg_values_supported": [
                    "ES256",
                ],
                "pushed_authorization_request_endpoint": AUTH_URL.to_owned()+"/par/request",
            }
        ));

        metadata.unwrap()
    }

    pub fn sample_credential_offer() -> Value {
        json!(
            {
                "credential_issuer": ISSUER_URL,
                "credential_configuration_ids": [
                    CRED_DEF_ID
                ],
                "grants": {
                    "authorization_code": {}
                }
            }
        )
    }

    pub fn sample_credential_definition() -> CredDefMetadata {
        let cred_def = serde_json::from_value(json!({
            "$key$": CRED_DEF_ID,
            "format": "dc+sd-jwt",
            "scope": "SD_JWT_cred",
            "cryptographic_binding_methods_supported": [
                "jwk"
            ],
            "credential_signing_alg_values_supported": [
                "ES256"
            ],
            "proof_types_supported": {
                "jwt": {
                "proof_signing_alg_values_supported": [
                    "ES256"
                ]
                }
            },
            "vct": "SD_JWT_cred",
            "credential_metadata": {
                "claims": [
                    { "path": ["given_name"] },
                    { "path": ["family_name"] },
                    { "path": ["dob"] },
                ]
            }
        }));

        cred_def.unwrap()
    }

    pub async fn sample_access_token() -> AccessToken {
        AccessToken::new(access_token(Some(SCOPE)).await)
    }

    pub fn fake_access_token() -> AccessToken {
        AccessToken::new("".to_string())
    }

    /// Signs an OID4VCI proof-of-possession JWT bound to the issuer and the
    /// shared nonce.
    pub async fn sample_proof_jwt() -> String {
        let kms = FixtureKms::new();
        let key = FixtureKey::create_default(&kms).await.expect("fixture key");
        FixtureProofOfPossession::builder(&key)
            .audience(ISSUER_URL)
            .nonce(NONCE)
            .build()
            .await
            .expect("proof of possession")
    }

    pub struct SampleCredentialRequest {}

    impl SampleCredentialRequest {
        pub async fn with_cred_configuration_id() -> CredentialRequest {
            let proof = sample_proof_jwt().await;
            serde_json::from_value(json!(
                {
                    "credential_configuration_id":"SD_JWT_cred_sample",
                    "proofs": {
                        "jwt": [ proof ],
                    },
                }
            ))
            .unwrap()
        }

        pub async fn with_cred_configuration_id_and_multiple_proofs() -> CredentialRequest {
            let proof = sample_proof_jwt().await;
            serde_json::from_value(json!(
                {
                    "credential_configuration_id":"SD_JWT_cred_sample",
                    "proofs": {
                        "jwt": [proof.clone(), proof.clone(), proof],
                    },
                }
            ))
            .unwrap()
        }

        pub fn with_empty_proofs() -> CredentialRequest {
            serde_json::from_value(json!(
                {
                    "credential_configuration_id":"SD_JWT_cred_sample",
                    "proofs": {
                        "jwt": [],
                    },
                }
            ))
            .unwrap()
        }

        pub async fn with_cred_identifier() -> CredentialRequest {
            let proof = sample_proof_jwt().await;
            serde_json::from_value(json!(
                {
                    "credential_identifier":"CivilEngineeringDegree-2023",
                    "proofs": {
                        "jwt": [ proof ],
                    },
                }
            ))
            .unwrap()
        }
    }

    pub fn sample_cred_response(sd_jwt: &str) -> CredentialResponse {
        let cred_response = serde_json::from_value(json!(
            {
                "credentials": [{"credential": sd_jwt}],
                "notification_id": NOTIFICATION_ID
            }
        ));
        cred_response.unwrap()
    }

    pub fn sample_batch_cred_response(sd_jwt: &str) -> CredentialResponse {
        let cred_response = serde_json::from_value(json!(
            {
                "credentials": [{"credential": sd_jwt}, {"credential": sd_jwt}],
                "notification_id": NOTIFICATION_ID
            }
        ));
        cred_response.unwrap()
    }

    pub fn sample_claims() -> Claims {
        serde_json::from_value(json!( {
            "vct": "SD_JWT_cred",
            "given_name": "John",
            "family_name": "Doe",
            "dob": "09/09/1989",
        }))
        .unwrap()
    }

    pub fn sample_introspect_response() -> Value {
        let resp = json!({
            "exp":1726846647,
            "iat":1726811031,
            "auth_time":1726810647,
            "jti":"cfbd5482-3cfa-4aed-b2f4-d65fb858b42e",
            "iss":"http://localhost:8080",
            "sub":"60b8ba5f-c73f-4976-b0da-48d0e53335de",
            "typ":"Bearer",
            "azp":"wallet-dev",
            "sid":"1fe84eb7-1911-40eb-8dcf-db3607a68d8f",
            "allowed-origins":["/*"],
            "scope":"SD_JWT_cred_scope",
            "client_id":"wallet-dev",
            "username":"tneal",
            "token_type":"Bearer",
            "active":true
        });

        resp
    }

    pub fn sample_offer_with_auth_code_grant(cred_def_id: Option<&str>) -> CredentialOfferParams {
        let auth_code_grant = AuthorizationCodeGrant::new(None, None)
            .set_authorization_server(Some(IssuerUrl::new(AUTH_URL.to_string()).unwrap()));

        CredentialOfferParams::new(
            IssuerUrl::new(ISSUER_URL.to_string()).unwrap(),
            vec![CredentialConfigurationId::new(
                cred_def_id.unwrap_or(CRED_DEF_ID).to_string(),
            )],
            Some(CredentialOfferGrants::new(Some(auth_code_grant), None)),
            HashMap::default(),
        )
    }

    pub fn sample_offer_with_pre_auth_code_grant(code: &str) -> CredentialOfferParams {
        let pre_auth_grant = PreAuthorizedCodeGrant::new(PreAuthorizedCode::new(code.to_string()))
            .set_authorization_server(Some(IssuerUrl::new(AUTH_URL.to_string()).unwrap()));

        CredentialOfferParams::new(
            IssuerUrl::new(ISSUER_URL.to_string()).unwrap(),
            vec![],
            Some(CredentialOfferGrants::new(None, Some(pre_auth_grant))),
            HashMap::default(),
        )
    }
}
