pub(crate) mod oid4vp;

use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::vault::CredentialEntry;
use equs_sdk::vc::claims::Claims;
use equs_sdk::vc::oid4vci::{AuthorizationMetadata, IssuerMetadata};
use equs_sdk::vc::oid4vp::{CredentialsFindResult, Holder, ResolvedAuthRequest};
use serde_json::json;
use std::collections::HashMap;
use test_fixtures::access_token::AccessToken;
use test_fixtures::keys::FixtureKey;
use url::Url;

pub const AUTHZ_URL: &str = "https://authz-backend.com";
pub const ISSUER_URL: &str = "https://issuer-backend.com";

pub const SCOPE: &str = "SD_JWT_cred";
pub const VERIFIER_ID: &str = "ver-id";
pub const VC_TYPE: &str = "https://credentials.example.com/identity_credential";

/// Mints a bearer access token carrying `scope: SCOPE`, as a Keycloak-issued
/// token would for the authorization-code flow the E2E suite exercises. The
/// signing key is generated fresh per call and discarded — these tests only
/// ever decode the token's `scope` claim (`validate_scope`) or hand it to a
/// mock introspection endpoint that ignores its content.
pub async fn access_token() -> String {
    let kms = LocalKms::new();
    let key = FixtureKey::create_default(&kms)
        .await
        .expect("fixture key creation should succeed");

    AccessToken::builder(&key)
        .scope(SCOPE)
        .build()
        .await
        .expect("access token fixture should build")
}

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
            "batch_credential_issuance": {
                "batch_size": 2
            },
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
