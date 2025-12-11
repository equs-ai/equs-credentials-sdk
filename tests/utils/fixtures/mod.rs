pub(crate) mod oid4vp;

use agent_sdk::vault::CredentialEntry;
use agent_sdk::vc::claims::Claims;
use agent_sdk::vc::oid4vci::{AuthorizationMetadata, IssuerMetadata};
use agent_sdk::vc::oid4vp::{CredentialsFindResult, Holder, ResolvedAuthRequest};
use serde_json::json;
use std::collections::HashMap;
use url::Url;

pub const AUTHZ_URL: &str = "https://authz-backend.com";
pub const ISSUER_URL: &str = "https://issuer-backend.com";

// header:
// {
//   "alg": "RS256",
//   "typ": "JWT",
//   "kid": "PclYP6vRk1LpKDfjSO2Da35rmGRfi9362CpREyJf8p0"
// }
//
// payload:
// {
//   "exp": 1759734659,
//   "iat": 1759734359,
//   "auth_time": 1759734105,
//   "jti": "onrtac:415f60df-5dc3-d219-06ad-2cf0618e6225",
//   "iss": "http://localhost:8080/realms/pid-issuer-realm",
//   "sub": "60b8ba5f-c73f-4976-b0da-48d0e53335de",
//   "typ": "Bearer",
//   "azp": "wallet-dev",
//   "sid": "e1de0faa-efd6-f290-22df-5f2caa56981a",
//   "allowed-origins": [
//     "/*",
//     "http://localhost:3000"
//   ],
//   "scope": "SD_JWT_cred"
// }
pub const ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlBjbFlQNnZSazFMcEtEZmpTTzJEYTM1cm1HUmZpOTM2MkNwUkV5SmY4cDAifQ.eyJleHAiOjE3NTk3MzQ2NTksImlhdCI6MTc1OTczNDM1OSwiYXV0aF90aW1lIjoxNzU5NzM0MTA1LCJqdGkiOiJvbnJ0YWM6NDE1ZjYwZGYtNWRjMy1kMjE5LTA2YWQtMmNmMDYxOGU2MjI1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImUxZGUwZmFhLWVmZDYtZjI5MC0yMmRmLTVmMmNhYTU2OTgxYSIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiIsImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.Vzd-czyWV8NamelfLXFAGe5KlzNsI9BQyHD3jwMiW5n5skG3yAbXHohXJIDD5OFe2RdQVXspuqwA8Fdxd3wMVpgW8vPPjFrBD7zQWMLUstiZKniVJroSFAo8A1u9Lq9pb648gF4DxZWTiQAy-1mNOW8QVEcN6XBEHTkZ0YaMPO-lyXkeQOuY5J1Z9s7y8_4HBE0FjnJuFRraO8S8l1ixoCAObtzMfARld3rBPM_EVTYxfrT1_TCXcylKuqRoJGjE8fnCSJYworG0AP7LO0hPcKrvlG5oiW8Zr_V0yBp4OKdOtwukgJ0R0gmxzCf0bOQHl_mdRm0QTxYslNYIrfh_yw";
pub const SCOPE: &str = "SD_JWT_cred";
pub const VERIFIER_ID: &str = "ver-id";
pub const VC_TYPE: &str = "https://credentials.example.com/identity_credential";
pub fn sample_authz_url() -> Url {
    Url::parse(AUTHZ_URL).unwrap()
}

pub fn sample_issuer_url() -> Url {
    Url::parse(ISSUER_URL).unwrap()
}

pub fn sample_issuer_metadata() -> IssuerMetadata {
    let metadata = serde_json::from_value(json!(
        {
            "credential_issuer": ISSUER_URL,
            "authorization_servers": [AUTHZ_URL],
            "credential_endpoint": ISSUER_URL.to_owned()+"/credential",
            "nonce_endpoint": ISSUER_URL.to_owned()+"/nonce",
            "credential_configurations_supported": {
                "SD_JWT_cred_1": {
                    "format": "dc+sd-jwt",
                    "scope": SCOPE.to_owned(),
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
                    "vct": "SD_JWT_cred_1",
                    "credential_metadata": {
                        "claims": [
                            { "path": ["given_name"] },
                            { "path": ["family_name"] },
                            { "path": ["dob"] },
                        ]
                    },
                },
                "SD_JWT_cred_2": {
                    "format": "dc+sd-jwt",
                    "scope": SCOPE.to_owned(),
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
                    "vct": "SD_JWT_cred_2",
                    "credential_metadata": {
                        "claims": [
                            { "path": ["given_name"] },
                            { "path": ["family_name"] },
                            { "path": ["dob"] },
                        ]
                    }
                },
                "LDPVC_cred_1": {
                    "scope": SCOPE.to_owned(),
                    "cryptographic_binding_methods_supported": [
                        "jwk"
                    ],
                    "format": "ldp_vc",
                    "credential_signing_alg_values_supported": [
                        "Ed25519Signature2018",
                        "EcdsaSecp256k1Signature2019"
                    ],
                    "credential_definition": {
                        "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://w3id.org/citizenship/v1"
                        ],
                        "type": [
                            "VerifiableCredential",
                            "PermanentResidentCard"
                        ],
                    },
                    "credential_metadata": {
                        "claims": [
                            { "path": ["credentialSubject", "givenName"] },
                            { "path": ["credentialSubject", "residentSince"] },
                            { "path": ["credentialSubject", "birthDate"] },
                            { "path": ["credentialSubject", "birthCountry"] },
                            { "path": ["credentialSubject", "familyName"] },
                            { "path": ["credentialSubject", "gender"] },
                            { "path": ["credentialSubject", "commuterClassification"] },
                            { "path": ["credentialSubject", "gpa"] },
                        ]
                    }
                }
            }
        }
    ));

    metadata.unwrap()
}

pub fn sample_authorization_metadata(authz_url: &str) -> AuthorizationMetadata {
    let metadata = serde_json::from_value(json!(
        {
            "issuer": authz_url,
            "authorization_endpoint": authz_url.to_owned()+"/auth",
            "token_endpoint": authz_url.to_owned()+"/token",
            "introspection_endpoint": authz_url.to_owned()+"/protocol/openid-connect/token/introspect",
            "jwks_uri": authz_url.to_owned()+"/cert",
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
            "pushed_authorization_request_endpoint": authz_url.to_owned()+"/par/request",
        }
    ));

    metadata.unwrap()
}

pub fn sample_claims_sdjwt() -> Claims {
    serde_json::from_value(json!(
        {
            "given_name": "John",
            "family_name": "Doe",
            "dob": "09/09/1989",
        }
    ))
    .unwrap()
}

pub fn sample_claims_jsonld() -> Claims {
    serde_json::from_value(json!(
        {
            "type": ["PermanentResident", "Person"],
            "givenName": "Jane",
            "familyName": "Smith",
            "gender": "female",
            "residentSince": "2015-01-01",
            "commuterClassification": "C1",
            "birthCountry": "Arcadia",
            "birthDate": "1978-07-17"
        }
    ))
    .unwrap()
}

pub async fn find_vcs_to_present(
    holder: &dyn Holder,
    request_object: &ResolvedAuthRequest,
) -> HashMap<String, Vec<CredentialEntry>> {
    let found_creds = holder
        .find_vcs_for_presentation(request_object)
        .await
        .unwrap();
    let mut creds = HashMap::new();
    for (key, value) in found_creds {
        let CredentialsFindResult::Credentials(credentials) = value else {
            panic!("Expected credentials, got failure reason: {:?}", value);
        };
        creds.insert(key, credentials);
    }

    creds
}
