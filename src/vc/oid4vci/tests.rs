pub mod fixtures {
    use crate::nonce::{Nonce, NonceData};
    use crate::vc::oid4vci::{CredDefMetadata, CredentialRequest, CredentialResponse};
    use crate::vc::Claims;
    use oauth2::AccessToken;
    use oid4vci::core::metadata::IssuerMetadata;
    use oid4vci::core::profiles::w3c::ldp::CredentialDefinitionLD;
    use oid4vci::core::profiles::w3c::CredentialDefinition;
    use oid4vci::metadata::AuthorizationMetadata;
    use serde_json::{json, Value};
    use time::OffsetDateTime;

    pub const ISSUER_URL: &str = "https://issuer-backend.com";
    pub const AUTH_URL: &str = "https://authz-backend.com";
    pub const TOKEN_INTROSPECT_URL: &str =
        "https://authz-backend.com/protocol/openid-connect/token/introspect";
    pub const JWKS_URL: &str = "http://issuer.org/certs";
    pub const NONCE: &str = "KB50VOm9I-kPLT9mAACV8g";

    // header:
    // {
    //     "alg": "RS256",
    //     "typ": "JWT",
    //     "kid": "PclYP6vRk1LpKDfjSO2Da35rmGRfi9362CpREyJf8p0"
    // }
    //
    // payload:
    // {
    //     "exp": 1724398494,
    //     "iat": 1724398194,
    //     "auth_time": 1724398182,
    //     "jti": "0b4fe390-4921-4042-b7e1-b03b3d196229",
    //     "iss": "http://localhost:8080/idp/realms/pid-issuer-realm",
    //     "sub": "60b8ba5f-c73f-4976-b0da-48d0e53335de",
    //     "typ": "Bearer",
    //     "azp": "wallet-dev",
    //     "sid": "f15b3e11-ff28-44df-8fcf-a77d24714a23",
    //     "allowed-origins": [
    //       "/*"
    //     ],
    //     "scope": "SD_JWT_cred"
    // }
    pub const ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA";
    pub const ACCESS_TOKEN_WITHOUT_SCOPE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdfQ.baJ-4kkcyLxf7v8J8e-qr9zlGFFM-Xa-P-K-Kg4iq8g";

    // claims used to generate credentilas:
    // {
    //     "vct": "SD_JWT_cred",
    //     "given_name": "John",
    //     "family_name": "Doe",
    //     "dob": "09/09/1989",
    // }
    //
    // header:
    // {
    //     "typ": "vc+sd-jwt",
    //     "alg": "ES256",
    //     "kid": "did:key:zDnaeujPqZ5EjHmfkrzYweLfMqr8aqA3ot3Btc4Fe9tyLqkmR#zDnaeujPqZ5EjHmfkrzYweLfMqr8aqA3ot3Btc4Fe9tyLqkmR"
    // }
    //
    // payload:
    // {
    //     "_sd": [
    //       "CT5o1LfNWDOKOxx42BYG4754lZHy6t0nOPkFEdfoqoM",
    //       "K7ma0NfqGC_3LPtmvqkrI4yrJlvH4TU69e7Iv-7EIo4",
    //       "reYaNFBWHzV17cvuq3rFjUI3Gx5Js_DmnUZSERd4hZs"
    //     ],
    //     "vct": "SD_JWT_cred",
    //     "sub": "did:key:zDnaenpntCkXnDCnaDk62LxNqPc4CMd32fbhiVsZV5KpPTG2c",
    //     "nbf": 1725533254,
    //     "_sd_alg": "sha-256",
    //     "iss": "did:key:zDnaeujPqZ5EjHmfkrzYweLfMqr8aqA3ot3Btc4Fe9tyLqkmR",
    //     "iat": 1725533254,
    //     "exp": 1757069254,
    //     "cnf": {
    //       "jwk": {
    //         "kty": "EC",
    //         "crv": "P-256",
    //         "x": "TLn66qbnPexKyFmgxucY3JZrdxBDjAsr-my2kWAbk8k",
    //         "y": "shYzyET8CrYW2MxOSABJLamJOLew-jPlOZxwSS6kXgc"
    //       }
    //     }
    // }

    pub const SD_JWT_CREDS: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiN6RG5hZXVqUHFaNUVqSG1ma3J6WXdlTGZNcXI4YXFBM290M0J0YzRGZTl0eUxxa21SIn0.eyJfc2QiOlsiQ1Q1bzFMZk5XRE9LT3h4NDJCWUc0NzU0bFpIeTZ0MG5PUGtGRWRmb3FvTSIsIks3bWEwTmZxR0NfM0xQdG12cWtySTR5ckpsdkg0VFU2OWU3SXYtN0VJbzQiLCJyZVlhTkZCV0h6VjE3Y3Z1cTNyRmpVSTNHeDVKc19EbW5VWlNFUmQ0aFpzIl0sInZjdCI6IlNEX0pXVF9jcmVkIiwic3ViIjoiZGlkOmtleTp6RG5hZW5wbnRDa1huRENuYURrNjJMeE5xUGM0Q01kMzJmYmhpVnNaVjVLcFBURzJjIiwibmJmIjoxNzI1NTMzMjU0LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiIsImlhdCI6MTcyNTUzMzI1NCwiZXhwIjoxNzU3MDY5MjU0LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19fQ.CBBzIiTjRs2bmKENQcRY14wVnl2vnIjJY9u3AYrA9KQDjqCXZXSzoxQlripAM6Ud_QaYNrZcHK2EVo4QlH3k9w~WyJvMFR4dEw4QWh1TFJXUmduSDk4NF9RIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ2SVMzZXNQTHlRUHRRZ0JMZ09GYWFnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJsaW81cXNVZHZJX3V3eUdiRmFtTnFRIiwgImRvYiIsICIwOS8wOS8xOTg5Il0~";

    pub const NOTIFICATION_ID: &str = "8fcc7362-dc77-4aaf-a953-fa56e39b22f7";
    pub const SCOPE: &str = "SD_JWT_cred";
    pub const CRED_DEF_ID: &str = "SD_JWT_cred_sample";
    pub const REQ_URI_CODE: &str = "fake_request_uri";
    pub const AUTH_REDIRECT_URL: &str = "urn:ietf:wg:oauth:2.0:oob";

    pub struct SampleIssuerMetadata {}
    impl SampleIssuerMetadata {
        pub fn with_sdjwtvc_conf() -> IssuerMetadata {
            let metadata = serde_json::from_value(json!(
                {
                    "credential_issuer": ISSUER_URL,
                    "authorization_servers": [AUTH_URL],
                    "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                    "credential_configurations_supported": {
                        CRED_DEF_ID: {
                            "format": "vc+sd-jwt",
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
                            "claims": {
                                "given_name": {},
                                "family_name": {},
                                "dob": {},
                            },
                        },
                    },
                }
            ));

            metadata.unwrap()
        }

        pub fn with_jwtvc_conf() -> IssuerMetadata {
            let metadata = serde_json::from_value(json!(
                {
                    "credential_issuer": ISSUER_URL,
                    "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
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
                    "credential_configurations_supported": {
                        SCOPE: {
                            "format": "jwt_vc_json-ld",
                        },
                    },
                }
            ));
            metadata.unwrap()
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
                    "authorization_code": {
                        "issuer_state":null
                    }
                }
            }
        )
    }

    pub fn sample_credential_definition() -> CredDefMetadata {
        let cred_def = serde_json::from_value(json!({
            "format": "vc+sd-jwt",
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
            "claims": {
                "given_name": {},
                "family_name": {},
                "dob": {}
            }
        }));

        cred_def.unwrap()
    }

    pub fn sample_access_token() -> AccessToken {
        oauth2::AccessToken::new(ACCESS_TOKEN.to_string())
    }

    pub fn sample_nonce() -> NonceData {
        NonceData {
            value: Nonce(NONCE.to_owned()),
            created: OffsetDateTime::now_utc(),
            expires_in: None,
        }
    }

    pub const SAMPLE_PROOF_JWT: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVucG50Q2tYbkRDbmFEazYyTHhOcVBjNENNZDMyZmJoaVZzWlY1S3BQVEcyYyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0In0.eyJhdWQiOiJodHRwczovL2lzc3Vlci1iYWNrZW5kLmNvbSIsIm5iZiI6MTcyNTM1MDQ4MCwiaWF0IjoxNzI1MzUwNDgwLCJleHAiOjQ4Nzg5NTA0ODAsIm5vbmNlIjoiS0I1MFZPbTlJLWtQTFQ5bUFBQ1Y4ZyJ9.v1bcMxXQDF4TqvR8ZJtL5-HcnuX9NgwErL9Qr9NFQ9IiAivWqoPpXizUFx8lpM26XUaY70FwGDFog17tbGysmg";

    pub struct SampleCredentialRequest {}

    impl SampleCredentialRequest {
        pub fn with_sdjwtvc_conf() -> CredentialRequest {
            serde_json::from_value(json!(
                {
                    "credential_identifier": CRED_DEF_ID,
                    "format":"vc+sd-jwt",
                    "vct":"SD_JWT_cred",
                    "proof":{
                        "proof_type":"jwt",
                        "jwt": SAMPLE_PROOF_JWT,
                    },
                    "credential_response_encryption":null
                }
            ))
            .unwrap()
        }

        pub fn with_jwtvcjson_conf() -> CredentialRequest {
            serde_json::from_value(json!(
                {
                    "credential_identifier": CRED_DEF_ID,
                    "format":"jwt_vc_json",
                    "credential_definition": CredentialDefinition::new(vec![]),
                }
            ))
            .unwrap()
        }

        pub fn with_jwtldvc_conf() -> CredentialRequest {
            serde_json::from_value(json!(
                {
                    "credential_identifier": CRED_DEF_ID,
                    "format":"jwt_vc_json-ld"
                }
            ))
            .unwrap()
        }

        pub fn with_ldpvc_conf() -> CredentialRequest {
            serde_json::from_value(json!(
                {
                    "credential_identifier": CRED_DEF_ID,
                    "format":"ldp_vc",
                    "credential_definition": CredentialDefinitionLD::new(CredentialDefinition::new(vec![]), vec![]),
                }
            ))
            .unwrap()
        }

        pub fn with_msomdoc_conf() -> CredentialRequest {
            serde_json::from_value(json!(
                {
                    "credential_identifier": CRED_DEF_ID,
                    "format":"mso_mdoc",
                        "doctype": "",
                }
            ))
            .unwrap()
        }
    }

    pub fn sample_cred_response() -> CredentialResponse {
        let cred_response = serde_json::from_value(json!(
            {
                "format":"vc+sd-jwt",
                "credential": SD_JWT_CREDS,
                "c_nonce":"0GtZieAoAL_3Zafyn6TgCA",
                "c_nonce_expires_in":86440,
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

    pub fn sample_jwks() -> Value {
        let jwks = json!({
          "keys": [
            {
              "kid": "PclYP6vRk1LpKDfjSO2Da35rmGRfi9362CpREyJf8p0",
              "kty": "RSA",
              "alg": "RS256",
              "use": "sig",
              "n": "qIMTnddR8yxBzXe1ue1Fx7kfjgY9jzsWm5ge7UWv5GWlFEoKjtDrGmPhtSwFTden3DiM4XiIBZ-5AbX_8fdnGxNUON1_GFBnLQv6q0eea9NRM8gtu_avM4nlVzErpdW1LKVm7C3JjjfdlivBEu6XcUZA4bUKNPaj6nwuqQsKstrcuPG32WapVszLDksfSowEVUIc9p__U0aasrfz6jM83jTwq_phHgEwZKxzfw-i055X0Q-JdIs01I27JkiNp0KG5Va-KU9GJBhcTw3QgpifmRc7_9WzmiiSbkxqsTZQwnQbxyShQJYZc0TdBudd7C3mRhDUNh-gdflCk06vCb5sbw",
              "e": "AQAB",
              "x5c": [
                "MIICrzCCAZcCBgGK8WCVpzANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBwaWQtaXNzdWVyLXJlYWxtMB4XDTIzMTAwMjE3MTA1M1oXDTMzMTAwMjE3MTIzM1owGzEZMBcGA1UEAwwQcGlkLWlzc3Vlci1yZWFsbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKiDE53XUfMsQc13tbntRce5H44GPY87FpuYHu1Fr+RlpRRKCo7Q6xpj4bUsBU3Xp9w4jOF4iAWfuQG1//H3ZxsTVDjdfxhQZy0L+qtHnmvTUTPILbv2rzOJ5VcxK6XVtSylZuwtyY433ZYrwRLul3FGQOG1CjT2o+p8LqkLCrLa3Ljxt9lmqVbMyw5LH0qMBFVCHPaf/1NGmrK38+ozPN408Kv6YR4BMGSsc38PotOeV9EPiXSLNNSNuyZIjadChuVWvilPRiQYXE8N0IKYn5kXO//Vs5ookm5MarE2UMJ0G8ckoUCWGXNE3QbnXewt5kYQ1DYfoHX5QpNOrwm+bG8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAg+H8Z/vQXxZ+kZZXupIOdZZCR3LuyLiZcselF2ldXaH44SUXBM2LbVvElLScg/DFak9Bp6+3fIrky56E9je/i8TpEtq0ey9sdncjAD070BmMHis7MIT5PdQkaESpCwJmN4HkVNrVFbsdiklnKIoSWmJ7IdARTPlYP3bDo6ts+0wxqc6dmFzePppVn+eMXr0HO4Il8ycctCaDr+iY4yvvi+OoOozm7yPBMzjFhYpLSV6Nisy5KABS3XTKJRmKelnC8jrqPl3lDWLXQx24PpIzxSRcRb6yPkClJWe7qFzckec7Zv5M7IRwLyxb0aWtK8m1xBlKXLNEWp+KXtrYGYHi0g=="
              ],
              "x5t": "f_nYDF5_zLbbZm1BxSroBsxCywU",
              "x5t#S256": "cxRALdyDtXe6fbJ16gv7GHqnd2G4zoOsUmKU1SJYA3c"
            }
          ]
        });

        jwks
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
}
