use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::{Nonce, ResponseMode};
use oid4vp::core::authorization_request::RequestIndirection;
use oid4vp::core::object::UntypedObject;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

use crate::vc::{Claims, Credential};
use crate::{storage, vc};

mod builder;
pub(crate) mod holder;
mod presentation_builder;
mod presentation_exchange;
pub(crate) mod verifier;

pub use builder::HolderBuilder;
pub use builder::VerifierBuilder;

// Data type
pub struct AuthorizationResponseMetadata {}
pub type CredentialMapping = HashMap<String, Vec<Credential>>;
pub type PresentationSubmission = oid4vp::presentation_exchange::PresentationSubmission;
pub type PresentationDefinition = oid4vp::presentation_exchange::PresentationDefinition;
pub type ClientMetadata = oid4vp::core::authorization_request::parameters::ClientMetadata;
pub type WalletMetadata = oid4vp::core::metadata::WalletMetadata;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAuthRequest {
    pub client_id: String,
    pub presentation_definition: PresentationDefinition,
    pub nonce: Nonce,
    pub response_mode: ResponseMode,
    pub response_uri: Url,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    client_id: String,
    pub request_object_jwt: String,
    authorization_endpoint: Url,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationResponse {
    pub vp_token: serde_json::Value,
    pub presentation_submission: PresentationSubmission,
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum VerifierError {
    #[error("Authorization Request creation failed: {0}")]
    RequestCreationFailed(String),
    #[error("Invalid Authorization Response: {0}")]
    InvalidResponse(String),
    #[error("Key resolution failed: {0}")]
    KeyResolutionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("{0} format not supported")]
    FormatNotSupported(String),
    #[error("Presentation verification failed {0}")]
    VerificationFailed(String),
    #[error("Failed to parse: {0}")]
    ParsingError(String),
    #[error("Required field missing: {0}")]
    MissingRequiredField(String),
    #[error("Storage Error: {0}")]
    StorageError(#[from] storage::Error),
    #[error("Submission not found: {0}")]
    SubmissionNotFound(String),
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum HolderError {
    #[error("vp format not supported")]
    VpFormatNotSupported,
    #[error("credential does not exist")]
    CredentialNotFound,
    #[error("could not validate Verifier: {0}")]
    RequestObjectVerification(String),
    #[error(transparent)]
    SpruceOid4Vp(#[from] anyhow::Error),
    #[error(transparent)]
    SpruceSsiJws(#[from] ssi::jws::Error),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    #[error(transparent)]
    VC(#[from] vc::core::Error),
    #[error("Url Parse Error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Presentation exchange error: {0}")]
    PresentationExchange(#[from] presentation_exchange::Error),
    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait Holder: Send + Sync {
    async fn get_authorization_request(
        &self,
        auth_req_uri: &str,
    ) -> Result<ResolvedAuthRequest, HolderError>;

    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>, HolderError>;

    async fn find_vcs_for_presentation(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<CredentialMapping, HolderError>;

    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        credential_mapping: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>, HolderError>;
}

#[async_trait]
pub trait Verifier: Send + Sync {
    async fn create_authorization_request(
        &self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        response_uri: Url,
    ) -> Result<AuthorizationRequest, VerifierError>;

    async fn verify_presentation(
        &self,
        authorization_response: &AuthorizationResponse,
    ) -> Result<Claims, VerifierError>;
}

const DEFAULT_CLIENT_METADATA: &str = r#"{
    "vp_formats": {
        "vc+sd-jwt": {
            "alg": [
                "EdDSA",
                "ES256"
            ]
        }
    }
}"#;

pub fn default_client_metadata() -> ClientMetadata {
    ClientMetadata::try_from(
        serde_json::from_str::<serde_json::Value>(DEFAULT_CLIENT_METADATA).unwrap(),
    )
    .unwrap()
}

const DEFAULT_WALLET_METADATA: &str = r#"{
    "issuer": "https://self-issued.me/v2",
    "authorization_endpoint": "openid4vp://",
    "response_types_supported": [
        "vp_token"
    ],
    "vp_formats_supported":
    {
        "vc+sd-jwt": {
            "alg_values_supported": ["EdDSA", "ES256"]
        }
    },
    "client_id_schemes_supported": [
        "did"
    ],
    "request_object_signing_alg_values_supported": [
        "EdDSA",
        "ES256"
    ]
}"#;

pub fn default_wallet_metadata() -> WalletMetadata {
    WalletMetadata::try_from(
        serde_json::from_str::<UntypedObject>(DEFAULT_WALLET_METADATA).unwrap(),
    )
    .unwrap()
}

pub enum AuthorizationUrlType {
    Reference(Url),
    Value,
}

pub fn auth_request_as_url(req: &AuthorizationRequest, type_: AuthorizationUrlType) -> Url {
    let request_indirection = match type_ {
        AuthorizationUrlType::Value => RequestIndirection::ByValue(req.request_object_jwt.clone()),
        AuthorizationUrlType::Reference(at) => RequestIndirection::ByReference(at),
    };
    use oid4vp::core::authorization_request::AuthorizationRequest as SpruceAuthorizationRequest;

    SpruceAuthorizationRequest {
        client_id: req.client_id.clone(),
        request_indirection,
    }
    .to_url(req.authorization_endpoint.clone())
    .unwrap()
}

#[cfg(test)]
pub mod test_utils {
    use std::str::FromStr;

    use crate::did::didkey::DIDKey;
    use crate::did::universal::UniversalResolver;
    use crate::did::{DIDResolver, DID};
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::kms;
    use crate::kms::{KeyID, Kms};
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata, VPMetadata};
    use crate::vc::formats::API;
    use crate::vc::oid4vp::verifier::VerifierMetadata;
    use crate::vc::oid4vp::{default_client_metadata, AuthorizationResponse};
    use oid4vci::openidconnect::Nonce;

    use oid4vp::presentation_exchange::PresentationDefinition;
    use serde_json::{json, Value as Json};
    use ssi::did::DIDURL;

    const TEST_PRESENTATION_DEFINITION: &str = r#"{
        "id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
        "input_descriptors": [
            {
                "id": "Identity-1",
                "name": "Identity VC",
                "purpose": "We want an identity",
                "format": {
                    "vc+sd-jwt": {
                        "alg": ["EdDSA", "ES256K"]
                    }
                 },
                "constraints": {
                    "fields": [
                        {
                            "path": [
                                "$.vct",
                                "$.name"
                            ]
                        }
                    ]
                }
            }
        ]
    }"#;

    const TEST_PRESENTATION_SUBMISSION: &str = r#"{
        "id": "725199a1-6fbe-4447-be06-a0f9857e32fd",
        "definition_id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
        "descriptor_map": [
            {
                "id": "Identity-1",
                "format": "vc+sd-jwt",
                "path": "$"
            }
        ]
    }"#;

    pub async fn create_test_verifier_metadata(
        did_resolver: &UniversalResolver,
        kms: &LocalKms,
    ) -> VerifierMetadata {
        let (verifier_kid, verifier_key_handle, verifier_did, verifier_vm_id) =
            generate_did_key_and_vm(kms, did_resolver).await;

        VerifierMetadata {
            client_id: verifier_did.to_owned(),
            key_metadata: KeyMetadata {
                did_url: verifier_vm_id,
                kid: verifier_kid,
            },
            client_metadata: default_client_metadata(),
        }
    }

    pub fn create_test_presentation_definition() -> PresentationDefinition {
        serde_json::from_str(TEST_PRESENTATION_DEFINITION).unwrap()
    }

    pub async fn create_authorization_response(
        verifier_id: &str,
        nonce: &str,
        claims: &Json,
    ) -> AuthorizationResponse {
        let kms = LocalKms::new();
        let (issuer_kid, issuer_key_handle, issuer_did) = generate_did_key(&kms).await;
        let issuer_did_url = DIDURL::from_str(&issuer_did).unwrap();

        let (holder_kid, holder_key_handle, holder_did) = generate_did_key(&kms).await;
        let holder_did_url = DIDURL::from_str(&holder_did).unwrap();

        let vc = SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(claims),
            (&issuer_did_url, issuer_key_handle),
            (&holder_did_url, holder_key_handle.clone()),
            VCMetadata {
                vct: "https://credentials.example.com/identity_credential".to_owned(),
                lifetime: time::Duration::days(365),
                disclosures: vec!["$.name".to_owned(), "$.surname".to_owned()],
            },
        )
        .await
        .unwrap();

        let vp = SdJwtAPI::create_vp(
            &vc,
            (&holder_did_url, holder_key_handle),
            Nonce::new(nonce.to_string()),
            verifier_id,
            VPMetadata {
                disclosures: json!({
                    "name" : true
                })
                .as_object()
                .unwrap()
                .to_owned(),
            },
        )
        .await
        .unwrap();

        AuthorizationResponse {
            vp_token: json!(vp),
            presentation_submission: serde_json::from_str(TEST_PRESENTATION_SUBMISSION).unwrap(),
        }
    }

    pub async fn generate_did_key(kms: &LocalKms) -> (KeyID, KeyHandle, DID) {
        let (issuer_kid, issuer_key_handle) = kms
            .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
            .await
            .unwrap();
        let issuer_did = DIDKey::new().generate(issuer_key_handle.clone()).unwrap();

        (issuer_kid, issuer_key_handle, issuer_did)
    }

    pub async fn generate_did_key_and_vm(
        kms: &LocalKms,
        did_resolver: &UniversalResolver,
    ) -> (KeyID, KeyHandle, DID, String) {
        let (kid, key_handle, did) = generate_did_key(kms).await;
        let vm_id = did_resolver
            .resolve_verification_method(&did)
            .await
            .unwrap()
            .id;

        (kid, key_handle, did, vm_id)
    }
}

#[cfg(test)]
mod tests {
    use mockito::Server;
    use oid4vp::presentation_exchange::{PresentationDefinition, PresentationSubmission};
    use rstest::rstest;
    use serde_json::{json, Map, Value as Json, Value};
    use ssi::did::DIDURL;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use url::{form_urlencoded, Url};

    use crate::crypto::Alg;
    use crate::did::universal::UniversalResolver;
    use crate::did::DID;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::storage::InMemStorage;
    use crate::inmem::vault::InMemVault;
    use crate::vault::Vault;
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata};
    use crate::vc::formats::API;
    use crate::vc::oid4vp::holder::HolderService;
    use crate::vc::oid4vp::test_utils::{generate_did_key, generate_did_key_and_vm};
    use crate::vc::oid4vp::verifier::VerifierService;
    use crate::vc::oid4vp::Verifier;
    use crate::vc::oid4vp::{
        auth_request_as_url, AuthorizationResponseMetadata, AuthorizationUrlType,
    };
    use crate::vc::oid4vp::{AuthorizationResponse, Holder};
    use crate::vc::{oid4vp as api, Credential, CredentialMetadata, VCFormat};
    use crate::{crypto, kms, vc};

    type ValidateClaims = dyn FnOnce(Json);

    struct Oid4VpTestCredential {
        pub id: &'static str,
        pub vct: &'static str,
        pub claims: Value,
    }

    struct Oid4VpTestCase {
        pub credentials: Vec<Oid4VpTestCredential>,
        pub presentation_definition: PresentationDefinition,
        pub validate: Box<ValidateClaims>,
    }

    fn single_presentation_case() -> Oid4VpTestCase {
        let identity = Oid4VpTestCredential {
            id: "Identity-1",
            vct: "https://credentials.example.com/identity_credential",
            claims: json!({
                "name": "John",
                "surname": "Doe",
                "address": "221B Baker Street",
                "date": "09/09/1989",
            }),
        };

        let presentation_definition = serde_json::from_value(json!({
            "id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
            "input_descriptors": [
                {
                    "id": "Identity-1",
                    "name": "Identity VC",
                    "purpose": "We want an identity",
                    "format": {
                        "vc+sd-jwt": {
                            "alg": ["EdDSA", "ES256K"]
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
            ]
        }))
        .unwrap();

        let validate: Box<ValidateClaims> = Box::new(|claims| {
            assert_eq!(
                claims["Identity-1"]["vct"],
                json!("https://credentials.example.com/identity_credential")
            );
            assert_eq!(claims["Identity-1"]["name"], json!("John"));
        });

        Oid4VpTestCase {
            credentials: vec![identity],
            presentation_definition,
            validate,
        }
    }

    fn multiple_presentation_case() -> Oid4VpTestCase {
        let identity = Oid4VpTestCredential {
            id: "Identity-1",
            vct: "https://credentials.example.com/identity_credential",
            claims: json!({
                "name": "John",
                "surname": "Doe",
                "address": "221B Baker Street",
                "date": "09/09/1989",
            }),
        };

        let degree = Oid4VpTestCredential {
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

        let presentation_definition = serde_json::from_value(json!({
            "id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
            "input_descriptors": [
                {
                    "id": "Identity-1",
                    "name": "Identity VC",
                    "purpose": "We want an identity",
                    "format": {
                        "vc+sd-jwt": {
                            "alg": ["EdDSA", "ES256K"]
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
                },
                {
                    "id": "Degree-1",
                    "name": "Degree VC",
                    "format": {
                        "vc+sd-jwt": {
                            "alg": ["EdDSA", "ES256K"]
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
            ]
        }))
        .unwrap();

        let validate: Box<ValidateClaims> = Box::new(|claims| {
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
            credentials: vec![identity, degree],
            presentation_definition,
            validate,
        }
    }

    #[rstest]
    #[case::single_presentation(single_presentation_case())]
    #[case::multiple_presentation(multiple_presentation_case())]
    #[tokio::test]
    async fn execute_oid4vp_flow(#[case] test_case: Oid4VpTestCase) {
        println!("7. Store Credential");
        let holder_kms = LocalKms::new();
        let (holder_kid, holder_kh, holder_did, holder_vm) =
            generate_did_key_and_vm(&holder_kms, &UniversalResolver::new()).await;
        let holder_did_url = DIDURL::from_str(&holder_did).unwrap();

        let holder_vault = InMemVault::new();

        // Create and store VCs
        for credential in &test_case.credentials {
            let (vc, vc_meta) = create_vc(
                credential.vct,
                &holder_did_url,
                holder_kh.clone(),
                credential.claims.clone(),
            )
            .await;
            holder_vault.store_credential(vc, &vc_meta).await.unwrap();
        }

        // Create Holder and Verifier
        let holder = holder(holder_did, holder_vm, holder_kid, holder_kms, holder_vault).await;

        let verifier = verifier().await;

        // Generate mocks
        let mut verifier_server = Server::new_async().await;
        let verifier_base_url = verifier_server.url();

        println!("8.1 Verifier: Create Authorization Request");
        // TODO: We should not use a test constant for Presentation Definition here,
        //  we need to build a new one (as every Verifier will build it).
        let nonce = "n0NcE";
        let response_uri: Url = format!("{}/auth", &verifier_base_url).parse().unwrap();
        let auth_request = verifier
            .create_authorization_request(&test_case.presentation_definition, nonce, response_uri)
            .await
            .unwrap();

        let request_uri: Url = format!("{}/req-object", &verifier_base_url)
            .parse()
            .unwrap();
        let by_value = auth_request_as_url(&auth_request, AuthorizationUrlType::Value);
        let by_reference = auth_request_as_url(
            &auth_request,
            AuthorizationUrlType::Reference(
                format!("{}/req-object", &verifier_base_url)
                    .parse()
                    .unwrap(),
            ),
        );

        println!("Request object passed by value: {}", by_value);
        println!("Request object passed by reference: {}", by_reference);

        mock_request_uri_endpoint(&mut verifier_server, &auth_request.request_object_jwt);
        let response_mutex = mock_response_uri_endpoint(&mut verifier_server);

        println!("8.2 Holder: Get Authorization Request");
        let request_object = holder
            .get_authorization_request(by_reference.as_str())
            .await
            .unwrap();

        println!("{:?}", &request_object);

        println!("9. Present Credential Auto");
        holder
            .present_credentials_auto(&request_object, &AuthorizationResponseMetadata {})
            .await
            .unwrap();

        println!("10. Verify Presentation");
        let auth_response = response_mutex.lock().await.clone().unwrap();

        println!("{:?}", auth_response);

        let claims = verifier.verify_presentation(&auth_response).await.unwrap();

        println!("Presentation Claims: {}", claims);

        (test_case.validate)(claims);
    }

    fn mock_request_uri_endpoint(verifier_server: &mut Server, request_object_jwt: &str) {
        verifier_server
            .mock("GET", "/req-object")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body(request_object_jwt)
            .create();
    }

    fn mock_response_uri_endpoint(
        verifier_server: &mut Server,
    ) -> Arc<Mutex<Option<AuthorizationResponse>>> {
        let authorization_response = Arc::new(Mutex::new(None));

        let response_clone = Arc::clone(&authorization_response);

        verifier_server
            .mock("POST", "/auth")
            .with_body_from_request(move |request| {
                let mut json_map = Map::new();
                for (key, value) in form_urlencoded::parse(request.body().unwrap()) {
                    // Try to parse the value as JSON, fall back to treating it as a plain string
                    let json_value: Json =
                        serde_json::from_str(&value).unwrap_or(Json::String(value.to_string()));
                    json_map.insert(key.to_string(), json_value);
                }

                let vp_token = json_map.get("vp_token").unwrap().clone();
                let presentation_submission: PresentationSubmission = serde_json::from_value(
                    json_map.get("presentation_submission").unwrap().clone(),
                )
                .unwrap();

                let mut locked_response = response_clone.try_lock().unwrap();
                *locked_response = Some(AuthorizationResponse {
                    vp_token,
                    presentation_submission,
                });

                vec![]
            })
            .create();

        authorization_response
    }

    async fn verifier() -> impl api::Verifier {
        let kms = LocalKms::new();
        let storage = InMemStorage::new();
        let did_resolver = UniversalResolver::new();

        let (kid, kh, did, vm_id) = generate_did_key_and_vm(&kms, &did_resolver).await;
        println!("Verifier DID: {}", did);

        let inner = vc::core::VerifierService::new(&did);
        VerifierService::new(
            inner,
            kms,
            did_resolver,
            storage,
            did,
            KeyMetadata {
                did_url: vm_id,
                kid,
            },
            None,
        )
    }

    async fn holder(
        holder_did: DID,
        holder_vm: String,
        holder_kid: kms::KeyID,
        kms: LocalKms,
        vault: InMemVault,
    ) -> impl api::Holder {
        let metadata = vc::core::HolderMetadata {
            client_id: holder_did.to_owned(),
            key_metadata: KeyMetadata {
                did_url: holder_vm,
                kid: holder_kid,
            },
        };
        let inner = vc::core::HolderService::new(kms, vault, metadata);

        let http_client = reqwest::Client::new();
        HolderService::new(inner, UniversalResolver::new(), None, http_client)
    }

    async fn create_vc(
        vct: &str,
        holder_did_url: &DIDURL,
        holder_kh: impl crypto::Key,
        claims: Json,
    ) -> (Credential, CredentialMetadata) {
        // Generate Issuer DID and Key
        let kms = LocalKms::new();
        let (kid, kh, did) = generate_did_key(&kms).await;
        println!("Issuer DID: {}", did);

        let did_url = DIDURL::from_str(&did).unwrap();

        let vc = SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(&claims),
            (&did_url, kh),
            (holder_did_url, holder_kh),
            VCMetadata {
                vct: vct.to_owned(),
                lifetime: time::Duration::days(365),
                disclosures: vec![
                    "$.name".to_owned(),
                    "$.surname".to_owned(),
                    "$.address".to_owned(),
                ],
            },
        )
        .await
        .unwrap();

        println!("Credential: {}", vc);

        let vc_meta = CredentialMetadata {
            type_: vct.to_string(),
            format: VCFormat::SdJwtVc,
            alg: Some(Alg::ES256),
            tags: vec![],
        };

        (Credential::SdJwt(vc), vc_meta)
    }
}
