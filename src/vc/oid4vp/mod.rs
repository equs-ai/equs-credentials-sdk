use async_trait::async_trait;
use url::Url;

use crate::vc;
use crate::vc::oid4vp::int::{AuthorizationRequest, AuthorizationResponse, PresentationDefinition};
use crate::vc::oid4vp::int::holder::{CredentialsMap, ResolvedAuthRequest};

pub mod int;
mod verifier;
mod holder;
//  --------- DATA MODEL -------------

pub type CredentialClaimsRaw = serde_json::Value;
pub struct AuthorizationResponseMetadata {}
pub type CredentialMapping = CredentialsMap;

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
}

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum HolderError {
    #[error("vp format not supported")]
    VpFormatNotSupported,
    #[error("credential does not exist")]
    CredentialNotFound,
    #[error("could not parse vp-format from presentation definition")]
    VpFormatParse,
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
    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait Holder {
    // Step 8.2
    // (Optional) AuthRequest can be sent out-of-band or by GET to auth-req-uri (this call)
    async fn get_authorization_request(
        &self,
        auth_req_uri: &str,
    ) -> Result<ResolvedAuthRequest, HolderError>;

    // Step 9
    // Assume credentials for presentations are selected automatically
    // If there is just one credential matching a presentation request - it's selected
    // If there are multiple selection matching - they are selected according to a default logic (such as take the first one)
    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>, HolderError>;

    // Step 9.1
    // Manual approval/consent of credentials to be used for presentation
    // Step 7A1 - find matching credentials
    async fn find_vcs_for_presentation(
        &self,
        auth_request: &ResolvedAuthRequest,
    ) -> Result<CredentialMapping, HolderError>;

    // Step 9.2
    // Manual approval/consent of credentials to be used for presentation
    // Step 5A2 - create presentation for a unambiguous Mapping where there is a VC for every presentation request item
    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        credential_mapping_selected: &CredentialMapping,
        metadata: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>, HolderError>;
}

#[async_trait]
pub trait Verifier {
    // Step 8.1
    // GET /<authorization_req_uri> or pass by value
    async fn create_authorization_request(
        &mut self,
        presentation_definition: &PresentationDefinition,
        nonce: &str,
        response_uri: Url,
    ) -> Result<AuthorizationRequest, VerifierError>;

    // Step 10
    // POST <authorization-response-uri>
    async fn verify_presentation(
        &mut self,
        authorization_response: &AuthorizationResponse,
    ) -> Result<CredentialClaimsRaw, VerifierError>;
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;
    use mockito::Server;
    use oid4vp::presentation_exchange::PresentationDefinition;
    use rstest::rstest;
    use serde_json::{json, Map, Value as Json, Value};
    use ssi::did::DIDURL;
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
    use crate::vc::oid4vp::int::test_utils::{generate_did_key, generate_did_key_and_vm};
    use crate::vc::oid4vp::int::{
        AuthorizationResponse, AuthorizationUrlType, PresentationSubmission,
    };
    use crate::vc::oid4vp::verifier::VerifierService;
    use crate::vc::oid4vp::{AuthorizationResponseMetadata};
    use crate::vc::oid4vp::Holder;
    use crate::vc::oid4vp::Verifier;
    use crate::vc::{oid4vp as api, Credential, CredentialMetadata, VCFormat};
    use crate::{crypto, kms, vc};

    type ValidateClaims = dyn FnOnce(Json) -> ();

    struct Oid4VpTestCredential {
        pub id: &'static str,
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
            claims: json!({
                "vct": "https://credentials.example.com/identity_credential",
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
                                "path": [
                                    "$.vct",
                                    "$.name"
                                ]
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
            claims: json!({
                "vct": "https://credentials.example.com/identity_credential",
                "name": "John",
                "surname": "Doe",
                "address": "221B Baker Street",
                "date": "09/09/1989",
            }),
        };

        let degree = Oid4VpTestCredential {
            id: "Degree-1",
            claims: json!({
                "vct": "https://credentials.example.com/degree_credential",
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
                                "path": [
                                    "$.vct",
                                    "$.name"
                                ]
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
                                "path": [
                                    "$.vct",
                                    "$.name"
                                ]
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
            assert_eq!(claims["Degree-1"]["degree"]["type"], json!("BachelorDegree"));
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
        let mut holder_kms = LocalKms::new();
        let (holder_kid, holder_kh, holder_did, holder_vm) =
            generate_did_key_and_vm(&mut holder_kms, &UniversalResolver::new()).await;
        let holder_did_url = DIDURL::from_str(&holder_did).unwrap();

        let mut holder_vault = InMemVault::new();

        // Create and store VCs
        for credential in &test_case.credentials {
            let (vc, vc_meta) = create_vc(
                credential.id,
                &holder_did_url,
                holder_kh.clone(),
                credential.claims.clone(),
            )
            .await;
            holder_vault.store_credential(vc, &vc_meta).await.unwrap();
        }

        // Create Holder and Verifier
        let holder = holder(holder_did, holder_vm, holder_kid, holder_kms, holder_vault).await;

        let mut verifier = verifier().await;

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
        let by_value = auth_request.as_url(AuthorizationUrlType::Value).unwrap();
        let by_reference = auth_request
            .as_url(AuthorizationUrlType::Reference(
                format!("{}/req-object", &verifier_base_url)
                    .parse()
                    .unwrap(),
            ))
            .unwrap();

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
                for (key, value) in form_urlencoded::parse(&request.body().unwrap()) {
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

    async fn verifier() -> impl Verifier {
        let mut verifier_kms = LocalKms::new();
        let (verifier_kid, verifier_key_handle, verifier_did, verifier_vm_id) =
            generate_did_key_and_vm(&mut verifier_kms, &UniversalResolver::new()).await;
        println!("Verifier DID: {}", verifier_did);

        let verifier_storage = InMemStorage::<String, Json>::new();
        let verifier_service = VerifierService::new(
            verifier_did,
            KeyMetadata {
                did_url: verifier_vm_id,
                kid: verifier_kid,
            },
            verifier_kms,
            verifier_storage,
        );

        verifier_service
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
        id: &str,
        holder_did_url: &DIDURL,
        holder_kh: impl crypto::Key,
        claims: Json,
    ) -> (Credential, CredentialMetadata) {
        // Generate Issuer DID and Key
        let mut issuer_kms = LocalKms::new();
        let (issuer_kid, issuer_kh, issuer_did) = generate_did_key(&mut issuer_kms).await;
        println!("Issuer DID: {}", issuer_did);

        let issuer_did_url = DIDURL::from_str(&issuer_did).unwrap();

        let vc = SdJwtAPI::create_vc(
            SdJwtAPI::resolve_claims(&claims),
            (&issuer_did_url, issuer_kh),
            (&holder_did_url, holder_kh),
            VCMetadata {
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
            id: id.to_string(),
            format: VCFormat::SdJwtVc,
            alg: Alg::ES256,
        };

        (vc::Credential::SdJwt(vc), vc_meta)
    }
}
