pub(crate) mod api;
pub(crate) mod holder;
pub(crate) mod verifier;

mod builder;
mod internal_error;
mod metadata;

pub use builder::Error as BuilderError;
pub use builder::HolderBuilder;
pub use builder::VerifierBuilder;
pub use internal_error::InternalError;

pub use api::*;

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
    use crate::vc::oid4vp::AuthorizationResponse;
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

    // TODO: move to the common test-util module
    pub async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
        let didkey = DIDKey::new();

        let (kid, kh) = kms
            .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
            .await
            .unwrap();

        let did = didkey.generate(kh).unwrap();

        let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

        (did, KeyMetadata { kid, did_url: vm })
    }
}

#[cfg(test)]
mod tests {
    use futures::executor;
    use oauth2::http::header::CONTENT_TYPE;
    use oauth2::http::{HeaderMap, HeaderValue, Method, StatusCode};
    use oauth2::HttpResponse;
    use oid4vp::presentation_exchange::PresentationDefinition;
    use rstest::rstest;
    use serde_json::{json, Value as Json, Value};
    use ssi::did::DIDURL;
    use std::collections::HashMap;
    use std::str::FromStr;
    use url::Url;

    use crate::crypto;
    use crate::crypto::Alg;
    use crate::did::universal::UniversalResolver;
    use crate::http::{HttpClient, MockHttpClient};
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::utils::http::test::mock_http_fn;
    use crate::vault::Vault;
    use crate::vc::core::KeyMetadata;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata};
    use crate::vc::formats::API;
    use crate::vc::oid4vp::test_utils::{
        create_did_and_key_metadata, generate_did_key, generate_did_key_and_vm,
    };
    use crate::vc::oid4vp::HolderBuilder;
    use crate::vc::oid4vp::{
        auth_request_as_url, AuthorizationResponseMetadata, AuthorizationUrlType,
    };
    use crate::vc::oid4vp::{AuthorizationResponse, Holder};
    use crate::vc::oid4vp::{Verifier, VerifierBuilder};
    use crate::vc::{Credential, CredentialMetadata, VCFormat};

    type ValidateClaims = dyn Fn(Json) + Send + Sync;

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

    const VERIFIER_URL: &str = "http://example.com";

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

        // Create mock http client
        let mut http_client = MockHttpClient::new();

        // Create Verifier
        let verifier = verifier().await;

        println!("8.1 Verifier: Create Authorization Request");
        // TODO: We should not use a test constant for Presentation Definition here,
        //  we need to build a new one (as every Verifier will build it).
        let nonce = "n0NcE";
        let response_uri: Url = format!("{}/auth", VERIFIER_URL).parse().unwrap();
        let auth_request = verifier
            .create_authorization_request(&test_case.presentation_definition, nonce, response_uri)
            .await
            .unwrap();

        let request_uri: Url = format!("{}/request", VERIFIER_URL).parse().unwrap();
        let by_value = auth_request_as_url(&auth_request, AuthorizationUrlType::Value);
        let by_reference = auth_request_as_url(
            &auth_request,
            AuthorizationUrlType::Reference(format!("{}/request", &VERIFIER_URL).parse().unwrap()),
        );

        println!("Request object passed by value: {}", by_value);
        println!("Request object passed by reference: {}", by_reference);

        mock_request_uri_endpoint(&mut http_client, auth_request.request_object_jwt.clone());

        // Bind mocked http call to verify presentation method
        mock_verify_presentation(Box::new(verifier), test_case.validate, &mut http_client);

        // Create Holder
        let holder = holder(
            http_client,
            holder_kms,
            holder_vault,
            KeyMetadata {
                did_url: holder_vm,
                kid: holder_kid,
            },
        )
        .await;

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
    }

    fn mock_request_uri_endpoint(http_client: &mut MockHttpClient, request_object_jwt: String) {
        mock_http_fn(
            http_client,
            Method::GET,
            Url::parse(VERIFIER_URL).unwrap().join("/request").unwrap(),
            move |req| {
                let resp = HttpResponse {
                    status_code: StatusCode::OK,
                    headers: HeaderMap::from_iter(vec![(
                        CONTENT_TYPE,
                        HeaderValue::from_str("text/plain").unwrap(),
                    )]),
                    body: Vec::from(request_object_jwt.to_owned()),
                };

                Ok(resp)
            },
            1.into(),
        );
    }

    fn mock_verify_presentation(
        verifier: Box<impl Verifier + 'static>,
        validate_claims: Box<ValidateClaims>,
        http_client: &mut MockHttpClient,
    ) {
        mock_http_fn(
            http_client,
            Method::POST,
            Url::parse(VERIFIER_URL).unwrap().join("/auth").unwrap(),
            move |request| {
                println!("10. Verify Presentation");
                let form: HashMap<String, String> =
                    serde_urlencoded::from_bytes(request.body.as_slice()).unwrap();
                // Retrieve vp_token and presentation_definition from submitted form
                let vp_token =
                    serde_json::from_str(form.get("vp_token").unwrap().as_str()).unwrap();
                let presentation_submission =
                    serde_json::from_str(form.get("presentation_submission").unwrap().as_str())
                        .unwrap();

                let auth_response = AuthorizationResponse {
                    vp_token,
                    presentation_submission,
                };

                let result = executor::block_on(verifier.verify_presentation(&auth_response));
                let claims = result.unwrap();
                println!("Presentation Claims: {}", claims);

                validate_claims(claims);

                Ok(HttpResponse {
                    status_code: StatusCode::OK,
                    headers: Default::default(),
                    body: vec![],
                })
            },
            1.into(),
        );
    }

    async fn verifier() -> impl Verifier {
        let kms = LocalKms::new();

        let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

        VerifierBuilder::new(kms, key_metadata, did)
            .build()
            .await
            .unwrap()
    }

    async fn holder(
        http_client: impl HttpClient,
        kms: LocalKms,
        vault: InMemVault,
        key_metadata: KeyMetadata,
    ) -> impl Holder {
        HolderBuilder::new(kms, vault, key_metadata, "wallet-dev".to_string())
            .with_http_client(http_client)
            .build()
            .await
            .unwrap()
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
