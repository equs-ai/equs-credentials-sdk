pub(crate) mod oid4vp;

use serde_json::json;
use url::Url;

use oid4vci::core::metadata::IssuerMetadata;
use oid4vci::metadata::AuthorizationMetadata;

use agent_sdk::vc::Claims;

pub const AUTHZ_URL: &str = "https://authz-backend.com";
pub const ISSUER_URL: &str = "https://issuer-backend.com";

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
pub const SCOPE: &str = "SD_JWT_cred";
pub const VERIFIER_ID: &str = "ver-id";
pub const VC_TYPE: &str = "https://credentials.example.com/identity_credential";
pub const NONCE_EXPIRES_IN: i64 = 86440;

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
          "credential_configurations_supported": {
            "SD_JWT_cred_1": {
              "format": "vc+sd-jwt",
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
              "claims": {
                "given_name": {},
                "family_name": {},
                "dob": {}
              }
            },
            "SD_JWT_cred_2": {
              "format": "vc+sd-jwt",
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
              "claims": {
                "given_name": {},
                "family_name": {},
                "dob": {}
              }
            },
            "LDPVC_cred_1": {
              "scope": SCOPE.to_owned(),
              "format": "ldp_vc",
              "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://w3id.org/citizenship/v1"
              ],
              "type": [
                  "VerifiableCredential",
                  "PermanentResident"
              ],
              "cryptographic_binding_methods_supported": [
                  "jwk"
              ],
              "cryptographic_suites_supported": [
                  "Ed25519Signature2018",
                  "EcdsaSecp256k1Signature2019"
              ],
              "credentials_definition": {
                  "@context": [
                      "https://www.w3.org/2018/credentials/v1",
                      "https://w3id.org/citizenship/v1"
                  ],
                  "type": [
                      "VerifiableCredential",
                      "PermanentResident"
                  ],
                  "credentialSubject": {
                      "givenName": {
                          "display": [
                              {
                                  "name": "Given Name",
                                  "locale": "en-US"
                              }
                          ]
                      },
                      "familyName": {
                          "display": [
                              {
                                  "name": "Surname",
                                  "locale": "en-US"
                              }
                          ]
                      },
                      "gender": {
                        "display": [
                            {
                                "name": "Gender",
                                "locale": "en-US"
                            }
                        ]
                      },
                      "birthDate": {},
                      "birthCountry": {},
                      "commuterClassification": {},
                      "residentSince": {},
                      "gpa": {
                          "display": [
                              {
                                  "name": "GPA"
                              }
                          ]
                      }
                  }
              },
              "display": [
                  {
                      "name": "University Credential",
                      "locale": "en-US",
                      "logo": {
                          "url": "https://exampleuniversity.com/public/logo.png",
                          "alt_text": "a square logo of a university"
                      },
                      "background_color": "#12107c",
                      "text_color": "#FFFFFF"
                  }
              ]
          },
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
