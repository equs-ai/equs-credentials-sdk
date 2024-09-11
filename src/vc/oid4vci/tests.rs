pub mod fixtures {
    use crate::vc::oid4vci::{CredentialRequest, CredentialResponse, Nonce};
    use crate::vc::Claims;
    use oauth2::AccessToken;
    use oid4vci::core::metadata::IssuerMetadata;
    use oid4vci::metadata::AuthorizationMetadata;
    use serde_json::{json, Value};

    pub const ISSUER_URL: &str = "https://issuer-backend.com";
    pub const AUTH_URL: &str = "https://authz-backend.com";
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
    pub const REQ_URI_CODE: &str = "fake_request_uri";

    pub fn sample_issuer_metadata() -> IssuerMetadata {
        let metadata = serde_json::from_value(json!(
            {
                "credential_issuer": ISSUER_URL,
                "authorization_servers": [AUTH_URL],
                "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
                "credential_configurations_supported": {
                    "SD_JWT_cred": {
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
                    "credential_definition": {
                        "type": "SD_JWT_cred",
                        "claims": {
                            "given_name": {},
                            "family_name": {},
                            "dob": {}
                        }
                        }
                    }
                }
            }
        ));

        metadata.unwrap()
    }

    pub fn sample_authorization_metadata() -> AuthorizationMetadata {
        let metadata = serde_json::from_value(json!(
            {
                "issuer": AUTH_URL,
                "authorization_endpoint": AUTH_URL.to_owned()+"/auth",
                "token_endpoint": AUTH_URL.to_owned()+"/token",
                "introspection_endpoint": AUTH_URL.to_owned()+"/protocol/openid-connect/token/introspect",
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
                    "SD_JWT_cred"
                ],
                "grants": {
                    "authorization_code": {
                        "issuer_state":null
                    }
                }
            }
        )
    }

    pub fn sample_access_token() -> AccessToken {
        oauth2::AccessToken::new(ACCESS_TOKEN.to_string())
    }

    pub fn sample_nonce() -> Nonce {
        serde_json::from_value(json!(NONCE)).unwrap()
    }

    pub fn sample_credential_request() -> CredentialRequest {
        serde_json::from_value(json!(
            {
                "credential_identifier":null,
                "format":"vc+sd-jwt",
                "vct":"SD_JWT_cred",
                "proof":{
                    "proof_type":"jwt",
                    "jwt":"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVucG50Q2tYbkRDbmFEazYyTHhOcVBjNENNZDMyZmJoaVZzWlY1S3BQVEcyYyIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0In0.eyJhdWQiOiJodHRwczovL2lzc3Vlci1iYWNrZW5kLmNvbSIsIm5iZiI6MTcyNTM1MDQ4MCwiaWF0IjoxNzI1MzUwNDgwLCJleHAiOjQ4Nzg5NTA0ODAsIm5vbmNlIjoiS0I1MFZPbTlJLWtQTFQ5bUFBQ1Y4ZyJ9.v1bcMxXQDF4TqvR8ZJtL5-HcnuX9NgwErL9Qr9NFQ9IiAivWqoPpXizUFx8lpM26XUaY70FwGDFog17tbGysmg"
                },
                "credential_response_encryption":null
            }
        )).unwrap()
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
}
