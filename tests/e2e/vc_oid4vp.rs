use crate::utils::fixtures::oid4vp::MockNonceHandler;
use crate::utils::fixtures::oid4vp::{NONCE, create_vc, generate_did_key_and_vm};
use agent_sdk::http::HttpClient;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::vault::Vault;
use agent_sdk::vc::oid4vp::{
    AuthResponseOptions, AuthorizationRequestMetadata, AuthorizationResponse,
    AuthorizationResponseMetadata, ClientMetadata, CredentialVerificationMetadata, IdTokenMetadata,
    PassAuthRequestObject, ResolvedPresentationQuery, ResponseMode, ResponseType,
};
use agent_sdk::vc::oid4vp::{AuthorizationResponseObject, Holder};
use agent_sdk::vc::oid4vp::{HolderBuilder, PresentationSession};
use agent_sdk::vc::oid4vp::{Verifier, VerifierBuilder};
use futures::executor;
use oauth2::HttpResponse;
use oauth2::http::header::CONTENT_TYPE;
use oauth2::http::{HeaderValue, Method};
use openid4vp::core::authorization_request::parameters::HttpMethodForAuth;
use rstest::rstest;
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

use crate::utils::helpers::create_did_keymetadata_keyhandle;
use crate::utils::http::HttpClientEmulator;

use crate::utils::fixtures::find_vcs_to_present;
use crate::utils::fixtures::oid4vp::{
    Oid4VpTestCase, STATE, VERIFIER_URL, ValidateClaimsFunc, dcql_multiple_sdjwt_presentation_case,
    presentation_exchange_multiple_sdjwt_presentation_case, single_jsonld_presentation_case,
    single_sdjwt_presentation_case,
};
use agent_sdk::inmem::nonce::LocalNonceHandler;

#[rstest]
#[case::single_jsonld_presentation(single_jsonld_presentation_case())]
#[case::single_sdjwt_presentation(single_sdjwt_presentation_case())]
#[case::multiple_sdjwt_presentation(presentation_exchange_multiple_sdjwt_presentation_case())]
#[tokio::test]
async fn credentials_presentation_and_verification(#[case] test_case: Oid4VpTestCase) {
    println!("7. Store Credential");
    let holder_kms = LocalKms::new();
    let (holder_key_metadata, holder_kh) = generate_did_key_and_vm(&holder_kms).await;
    let holder_vault = InMemVault::new();

    // Create and store VCs
    for credential in test_case.credentials {
        let (vc, vc_meta) = create_vc(
            credential.format,
            &holder_key_metadata.did_url,
            holder_key_metadata.kid.clone(),
            holder_kh.clone(),
            credential.claims,
        )
        .await;

        println!("\nvc: {:?}\n", vc);

        holder_vault.store_credential(vc, &vc_meta).await.unwrap();
    }

    // Create Verifier
    let verifier = build_verifier().await;

    println!("8.1 Verifier: Create Authorization Request");
    // TODO: We should not use a test constant for Presentation Definition here,
    //  we need to build a new one (as every Verifier will build it).
    let response_uri: Url = format!("{}/auth", VERIFIER_URL).parse().unwrap();
    let request_uri: Url = format!("{}/request", &VERIFIER_URL).parse().unwrap();
    let auth_response_options = AuthResponseOptions {
        type_: ResponseType::VpTokenIdToken,
        mode: ResponseMode::DirectPost,
        submission_uri: response_uri,
        state: Some(STATE.to_string()),
    };

    let (auth_request, session) = verifier
        .create_authorization_request(
            &ResolvedPresentationQuery::PresentationDefinition(test_case.presentation_definition),
            &AuthorizationRequestMetadata {
                transaction_data: None,
                auth_response_options,
                pass_auth_request_object: PassAuthRequestObject::ByReference {
                    uri: request_uri.clone(),
                    method: Some(HttpMethodForAuth::POST),
                },
            },
            None,
        )
        .await
        .unwrap();

    let http_client = prepare_http_client_for_holder(
        session.auth_request_jwt.clone().unwrap(),
        verifier,
        test_case.validate,
        session,
        false,
        Method::POST,
    );

    // Create Holder
    let holder = build_holder(http_client, holder_kms, holder_vault).await;

    println!("8.2 Holder: Get Authorization Request");
    let request_object = holder
        .get_authorization_request(&auth_request)
        .await
        .unwrap();

    println!("{:?}", &request_object);
    assert_eq!(
        serde_json::to_value(&request_object.client_metadata).unwrap(),
        serde_json::from_str::<serde_json::Value>(DEFAULT_CLIENT_METADATA).unwrap()
    );

    println!("9. Present Credentials");

    let auth_resp_metadata = AuthorizationResponseMetadata {
        claims_to_exclude: None,
        id_token_metadata: Some(IdTokenMetadata {
            key_metadata: holder_key_metadata,
            lifetime: time::Duration::minutes(5),
        }),
    };

    let creds_mapping = find_vcs_to_present(&holder, &request_object).await;
    holder
        .present_credentials(&request_object, &creds_mapping, &auth_resp_metadata)
        .await
        .unwrap();
}

#[rstest]
#[case::single_jsonld_presentation(single_jsonld_presentation_case())]
#[case::single_sdjwt_presentation(single_sdjwt_presentation_case())]
#[case::multiple_sdjwt_presentation(dcql_multiple_sdjwt_presentation_case())]
#[tokio::test]
async fn credentials_presentation_and_verification_with_dcql(#[case] test_case: Oid4VpTestCase) {
    println!("7. Store Credential");
    let holder_kms = LocalKms::new();
    let (holder_key_metadata, holder_kh) = generate_did_key_and_vm(&holder_kms).await;
    let holder_vault = InMemVault::new();

    // Create and store VCs
    for credential in test_case.credentials {
        let (vc, vc_meta) = create_vc(
            credential.format,
            &holder_key_metadata.did_url,
            holder_key_metadata.kid.clone(),
            holder_kh.clone(),
            credential.claims,
        )
        .await;

        println!("\nvc: {:?}\n", vc);

        holder_vault.store_credential(vc, &vc_meta).await.unwrap();
    }

    // Create Verifier
    let verifier = build_verifier().await;

    println!("8.1 Verifier: Create Authorization Request");
    // TODO: We should not use a test constant for Presentation Definition here,
    //  we need to build a new one (as every Verifier will build it).
    let response_uri: Url = format!("{}/auth", VERIFIER_URL).parse().unwrap();
    let request_uri: Url = format!("{}/request", &VERIFIER_URL).parse().unwrap();
    let auth_response_options = AuthResponseOptions {
        type_: ResponseType::VpTokenIdToken,
        mode: ResponseMode::DirectPost,
        submission_uri: response_uri,
        state: Some(STATE.to_string()),
    };

    let (auth_request, session) = verifier
        .create_authorization_request(
            &ResolvedPresentationQuery::DCQL(test_case.dcql.unwrap()),
            &AuthorizationRequestMetadata {
                transaction_data: None,
                auth_response_options,
                pass_auth_request_object: PassAuthRequestObject::ByReference {
                    uri: request_uri.clone(),
                    method: None,
                },
            },
            None,
        )
        .await
        .unwrap();

    let http_client = prepare_http_client_for_holder(
        session.auth_request_jwt.clone().unwrap(),
        verifier,
        test_case.validate,
        session,
        true,
        Method::GET,
    );

    // Create Holder
    let holder = build_holder(http_client, holder_kms, holder_vault).await;

    println!("8.2 Holder: Get Authorization Request");
    let request_object = holder
        .get_authorization_request(&auth_request)
        .await
        .unwrap();

    println!(
        "{}",
        &serde_json::to_string_pretty(&request_object).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&request_object.client_metadata).unwrap(),
        serde_json::from_str::<serde_json::Value>(DEFAULT_CLIENT_METADATA).unwrap()
    );

    println!("9. Present Credentials");

    let auth_resp_metadata = AuthorizationResponseMetadata {
        claims_to_exclude: None,
        id_token_metadata: Some(IdTokenMetadata {
            key_metadata: holder_key_metadata,
            lifetime: time::Duration::minutes(5),
        }),
    };

    let creds_mapping = find_vcs_to_present(&holder, &request_object).await;
    holder
        .present_credentials(&request_object, &creds_mapping, &auth_resp_metadata)
        .await
        .unwrap();
}

fn prepare_http_client_for_holder(
    request_object_jwt: String,
    verifier: impl Verifier + 'static,
    validate_claims_func: Box<ValidateClaimsFunc>,
    session: PresentationSession,
    is_dcql: bool,
    http_method_for_auth: Method,
) -> impl HttpClient {
    let mut http_client = HttpClientEmulator::new();

    http_client.add_handler(
        Url::parse(VERIFIER_URL).unwrap().join("/request").unwrap(),
        Box::new(move |req| {
            assert_eq!(req.method(), http_method_for_auth);
            if http_method_for_auth == Method::POST {
                assert!(
                    String::from_utf8(req.body().to_owned())
                        .unwrap()
                        .contains(NONCE)
                );
            }
            let mut resp = HttpResponse::new(Vec::from(request_object_jwt.to_owned()));
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));

            Ok(resp)
        }),
    );

    http_client.add_handler(
        Url::parse(VERIFIER_URL).unwrap().join("/auth").unwrap(),
        Box::new(move |req| {
            assert_eq!(req.method(), Method::POST);

            println!("10. Verify Presentation");
            let form: HashMap<String, String> = serde_urlencoded::from_bytes(req.body()).unwrap();
            // Retrieve vp_token and presentation_definition from submitted form
            let vp_token_str = form.get("vp_token").unwrap().as_str();
            let vp_token = match is_dcql {
                true => {
                    let vp_token: HashMap<String, Vec<Value>> =
                        serde_json::from_str(vp_token_str).unwrap();
                    serde_json::to_value(vp_token).unwrap()
                }
                false => serde_json::from_str(vp_token_str)
                    .unwrap_or(serde_json::to_value(vp_token_str).unwrap()),
            };
            println!(
                "vp_token: {}",
                serde_json::to_string_pretty(&vp_token).unwrap()
            );
            let presentation_submission = match is_dcql {
                true => None,
                false => {
                    serde_json::from_str(form.get("presentation_submission").unwrap().as_str())
                        .unwrap()
                }
            };
            let id_token = form.get("id_token").cloned();
            let state = form.get("state").cloned();
            assert_eq!(state.clone().unwrap(), STATE);

            let auth_response = AuthorizationResponseObject {
                vp_token,
                presentation_submission,
                id_token,
                state,
                transaction_data_response: None,
            };

            let result = executor::block_on(verifier.verify_presentation(
                &AuthorizationResponse::Plain(auth_response),
                &session,
                &CredentialVerificationMetadata::default(),
            ));
            let claims = result.unwrap();
            println!(
                "Presentation Claims: {}",
                serde_json::to_string_pretty(&claims).unwrap()
            );

            validate_claims_func(claims);

            Ok(HttpResponse::new(vec![]))
        }),
    );

    http_client
}

async fn build_verifier() -> impl Verifier {
    let kms = LocalKms::new();
    let nonce_gen = LocalNonceHandler::default();

    let (did, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;

    VerifierBuilder::new(kms, nonce_gen, key_metadata, did)
        .with_client_metadata(default_verifier_metadata())
        .build()
        .await
        .unwrap()
}

async fn build_holder(
    http_client: impl HttpClient,
    kms: LocalKms,
    vault: InMemVault,
) -> impl Holder {
    HolderBuilder::new(kms, vault, "wallet-dev".to_string(), http_client)
        .with_nonce_handler(Box::new(MockNonceHandler::default()))
        .build()
        .await
        .unwrap()
}

fn default_verifier_metadata() -> ClientMetadata {
    ClientMetadata::try_from(serde_json::from_str::<Value>(DEFAULT_CLIENT_METADATA).unwrap())
        .unwrap()
}

const DEFAULT_CLIENT_METADATA: &str = r#"{
    "vp_formats_supported": {
        "dc+sd-jwt": {
            "sd-jwt_alg_values": ["EdDSA", "ES256"],
            "kb-jwt_alg_values": ["EdDSA", "ES256"]
        },
        "ldp_vc": {
          "proof_type": [
            "Ed25519Signature2018",
            "EcdsaSecp256k1Signature2019"
          ]
        }
    },
    "subject_syntax_types_supported": [
        "did:key"
    ]
}"#;
