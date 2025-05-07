#![allow(dead_code)]

mod utils;

use crate::utils::fixtures::oid4vp::{
    multiple_sdjwt_presentation_case, single_jsonld_presentation_case,
    single_sdjwt_presentation_case, Oid4VpTestCase, Oid4VpTestCredentialFormat, ValidateClaimsFunc,
    STATE, VERIFIER_URL,
};
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver, DID, DIDURL};
use agent_sdk::http::HttpClient;
use agent_sdk::inmem::kms::{KeyHandle, LocalKms};
use agent_sdk::inmem::nonce::LocalNonceHandler;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::kms::Kms;
use agent_sdk::vault::Vault;
use agent_sdk::vc::claims::Claims;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::oid4vci::{
    CredentialOfferGrants, CredentialOfferParams, Holder, HolderBuilder, Issuer, IssuerBuilder,
    IssuerDiscovery, IssuerMetadata,
};
use agent_sdk::vc::oid4vp::Holder as Oid4vpHolder;
use agent_sdk::vc::oid4vp::{
    AuthResponseOptions, AuthorizationResponse, AuthorizationResponseMetadata, ClientMetadata,
    IdTokenMetadata, PassAuthRequestObject, PresentationSession, ResponseMode, ResponseType,
    Verifier, VerifierBuilder,
};
use agent_sdk::vc::{
    oid4vci, Credential, CredentialMetadata, VCFormatsAPI, VCFormatsJsonLdAPI, VCFormatsSdJwtAPI,
};
use agent_sdk::{crypto, kms};
use futures::executor;
use oauth2::http::header::CONTENT_TYPE;
use oauth2::http::StatusCode;
use oauth2::http::{HeaderValue, Method};
use oauth2::{HttpRequest, HttpResponse, TokenResponse};
use oid4vci::AuthorizationCodeGrant;
use rstest::rstest;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::{io, str};
use url::Url;
use utils::fixtures::{
    sample_authz_url, sample_claims_jsonld, sample_claims_sdjwt, sample_issuer_metadata,
    sample_issuer_url, ACCESS_TOKEN, AUTHZ_URL, SCOPE,
};
use utils::helpers::oid4vci::setup_http_static_handlers;
use utils::http::HttpClientEmulator;
use utils::test_resolver::TestDIDResolver;
use uuid::Uuid;

// tests simple oid4vc flow with test resolver
const CUSTOM_METHOD_NAME: &str = "test";
#[rstest]
#[case::token_validation_enabled(true)]
#[case::token_validation_disabled(false)]
#[tokio::test]
async fn authorized_code_flow_using_custom_did_resolver(#[case] validate_token: bool) {
    // Setting up mocks and fixtures
    let issuer_metadata = sample_issuer_metadata();

    let authz_code = Uuid::new_v4().to_string();
    let req_uri_code = Uuid::new_v4().to_string();
    let mut introspect_ep = None;

    if validate_token {
        introspect_ep = Some(sample_authz_url().join("/token/introspect").unwrap());
    }

    // 1. Creating issuer from issuer metadata
    let issuer = build_issuer_with_test_did_resolver(
        issuer_metadata.clone(),
        prepare_http_client_for_issuer(),
        introspect_ep,
    )
    .await;

    // 2. Creating offer
    let (offer, _) = issuer
        .create_credential_offer(
            vec!["SD_JWT_cred_1", "SD_JWT_cred_2", "LDPVC_cred_1"],
            &CredentialOfferGrants {
                authorization_code: Some(AuthorizationCodeGrant::new(None, None)),
                pre_authorized_code: None,
            },
        )
        .unwrap();

    let http_client_for_holder =
        prepare_http_client_for_holder(authz_code.clone(), req_uri_code.clone(), issuer);

    // 3.1 Creating holder from offer
    let kms = LocalKms::new();
    let holder =
        build_holder_with_test_did_resolver(offer, http_client_for_holder, kms.clone()).await;

    // 4. Holder has issuer metadata
    assert_eq!(&holder.get_issuer_metadata(), &issuer_metadata);

    // 5. Holder authorizes
    let token_response = holder
        .authz_code_flow_with_scope(SCOPE.into(), |url| {
            println!("Url {}", url);

            assert!(url.to_string().starts_with(AUTHZ_URL));
            assert!(url.query().unwrap().contains(&req_uri_code));

            async { Ok::<String, io::Error>(authz_code.to_owned()) }
        })
        .await
        .unwrap();

    println!("Token response {:?}", token_response);

    // 6.1 Holder requests SD_JWT_cred_1 credentials
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle_with_test_did_resolver(&kms).await;
    let response = holder
        .request_credential(
            token_response.access_token(),
            "SD_JWT_cred_1",
            &[key_metadata],
        )
        .await
        .unwrap();

    println!("Credential 1: {:?}", response.data);

    // 6.2 Holder requests LDPVC_cred_1 credentials with the same token
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle_with_test_did_resolver(&kms).await;
    let response = holder
        .request_credential(
            token_response.access_token(),
            "LDPVC_cred_1",
            &[key_metadata],
        )
        .await
        .unwrap();

    match response.data {
        oid4vci::CredentialResult::Credential {
            credentials: credential,
            ..
        } => {
            println!(
                "Credential 2: {}",
                serde_json::to_string_pretty(&credential).unwrap()
            );
        }
        _ => panic!("unexpected result"),
    }
}

// tests simple oid4vp flow with test resolver
#[rstest]
#[case::single_jsonld_presentation(single_jsonld_presentation_case())]
#[case::single_sdjwt_presentation(single_sdjwt_presentation_case())]
#[case::multiple_sdjwt_presentation(multiple_sdjwt_presentation_case())]
#[tokio::test]
async fn oid4vp_credentials_presentation_and_verification_with_custom_did_resolver(
    #[case] test_case: Oid4VpTestCase,
) {
    println!("7. Store Credential");
    let holder_kms = LocalKms::new();
    let (_, holder_key_metadata, holder_kh) =
        create_did_keymetadata_keyhandle_with_test_did_resolver(&holder_kms).await;
    let holder_vault = InMemVault::new();

    // Create and store VCs
    for credential in test_case.credentials {
        let (vc, vc_meta) = create_vc_with_test_did_resolver(
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
    let verifier = build_verifier_with_test_did_resolver().await;

    println!("8.1 Verifier: Create Authorization Request");
    // TODO: We should not use a test constant for Presentation Definition here,
    //  we need to build a new one (as every Verifier will build it).
    let response_uri: Url = format!("{}/auth", VERIFIER_URL).parse().unwrap();
    let request_uri: Url = format!("{}/request", &VERIFIER_URL).parse().unwrap();
    let auth_resp_options = AuthResponseOptions {
        type_: ResponseType::VpTokenIdToken,
        mode: ResponseMode::DirectPost,
        submission_uri: response_uri,
        state: Some(STATE.to_string()),
    };

    let (auth_request, session) = verifier
        .create_authorization_request(
            &test_case.presentation_definition,
            &auth_resp_options,
            &PassAuthRequestObject::ByReference(request_uri.clone()),
            None,
        )
        .await
        .unwrap();

    let http_client = prepare_holder_http_client_for_verifier(
        session.auth_request_jwt.clone().unwrap(),
        verifier,
        test_case.validate,
        session,
    );

    // Create Holder
    let holder =
        build_holder_for_oid4vp_with_test_did_resolver(http_client, holder_kms, holder_vault).await;

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

    println!("9. Present Credential Auto");

    let auth_resp_metadata = AuthorizationResponseMetadata {
        claims_to_exclude: None,
        id_token_metadata: Some(IdTokenMetadata {
            key_metadata: holder_key_metadata,
            lifetime: time::Duration::minutes(5),
        }),
    };

    holder
        .present_credentials_auto(&request_object, &auth_resp_metadata)
        .await
        .unwrap();
}

async fn credential_endpoint(issuer: &impl Issuer, req: HttpRequest) -> HttpResponse {
    let cred_req_str = std::str::from_utf8(req.body().as_slice()).unwrap();
    println!("Credential Request==============\n: {}", cred_req_str);
    let claims = if cred_req_str.contains("SD_JWT_cred") {
        sample_claims_sdjwt()
    } else if cred_req_str.contains("LDPVC_cred") {
        sample_claims_jsonld()
    } else {
        panic!("unsupported format of requested credential");
    };

    let cred_req = serde_json::from_slice(req.body().as_slice()).unwrap();

    println!("cred request from holder: {:?}", cred_req);

    let token = req.headers().get("Authorization").unwrap();
    let token = token
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_string();

    let result = issuer
        .issue_credential(&cred_req, &token, &claims, None)
        .await;

    println!("result: {:?}", result);

    match result {
        Ok(cred_resp) => HttpResponse::new(serde_json::to_vec(&cred_resp).unwrap()),
        Err(oid4vci::Error::Protocol { source }) => {
            let mut resp = HttpResponse::new(serde_json::to_vec(&source).unwrap());
            *resp.status_mut() = StatusCode::BAD_REQUEST;

            resp
        }
        _ => panic!(),
    }
}

fn prepare_http_client_for_issuer() -> impl HttpClient {
    let mut http_client = HttpClientEmulator::new();

    http_client.add_handler(
        sample_authz_url().join("/token/introspect").unwrap(),
        Box::new(|_| {
            Ok(HttpResponse::new(
                serde_json::to_vec(&json!({"active": true,})).unwrap(),
            ))
        }),
    );

    http_client
}

fn prepare_http_client_for_holder(
    authz_code: String,
    req_uri_code: String,
    issuer: impl Issuer + 'static,
) -> impl HttpClient {
    let mut http_client = HttpClientEmulator::new();

    setup_http_static_handlers(&mut http_client);

    http_client.add_handler(
        sample_authz_url().join("/par/request").unwrap(),
        Box::new(move |req| {
            assert_eq!(req.method(), Method::POST);

            let resp_body = serde_json::to_value(json!(
                {
                    "request_uri": "urn:ietf:params:oauth:request_uri:".to_owned() + &req_uri_code,
                    "expires_in": 86400,
                }
            ))
            .unwrap();
            let mut resp = HttpResponse::new(serde_json::to_vec(&resp_body).unwrap());
            *resp.status_mut() = StatusCode::CREATED;

            Ok(resp)
        }),
    );

    http_client.add_handler(
        sample_authz_url().join("/token").unwrap(),
        Box::new(move |req| {
            let req_body = str::from_utf8(req.body()).unwrap();

            assert!(req_body.contains(&format!("code={authz_code}")));
            assert_eq!(req.method(), Method::POST);

            let resp = json!({
                "access_token": ACCESS_TOKEN,
                "token_type": "bearer",
                "expires_in": 86400,
            });

            Ok(HttpResponse::new(serde_json::to_vec(&resp).unwrap()))
        }),
    );

    let nonce_future = executor::block_on(issuer.generate_nonce()).unwrap();
    http_client.add_handler(
        sample_issuer_url().join("/nonce").unwrap(),
        Box::new(move |_| {
            Ok(HttpResponse::new(
                serde_json::to_vec(&nonce_future).unwrap(),
            ))
        }),
    );

    http_client.add_handler(
        sample_issuer_url().join("/credential").unwrap(),
        Box::new(move |req| {
            let fut = credential_endpoint(&issuer, req);
            let result = executor::block_on(fut); // TODO: get rid of `block_on` here
            Ok(result)
        }),
    );

    http_client
}

fn prepare_holder_http_client_for_verifier(
    request_object_jwt: String,
    verifier: impl Verifier + 'static,
    validate_claims_func: Box<ValidateClaimsFunc>,
    session: PresentationSession,
) -> impl HttpClient {
    let mut http_client = HttpClientEmulator::new();

    http_client.add_handler(
        Url::parse(VERIFIER_URL).unwrap().join("/request").unwrap(),
        Box::new(move |req| {
            assert_eq!(req.method(), Method::GET);
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
            let vp_token = serde_json::from_str(vp_token_str)
                .unwrap_or(serde_json::to_value(vp_token_str).unwrap());
            let presentation_submission =
                serde_json::from_str(form.get("presentation_submission").unwrap().as_str())
                    .unwrap();
            let id_token = form.get("id_token").cloned();
            let state = form.get("state").cloned();
            assert_eq!(state.clone().unwrap(), STATE);

            let auth_response = AuthorizationResponse {
                vp_token,
                presentation_submission,
                id_token,
                state,
            };

            let result = executor::block_on(verifier.verify_presentation(&auth_response, &session));
            let claims = result.unwrap();
            println!("Presentation Claims: {:?}", claims);

            validate_claims_func(claims);

            Ok(HttpResponse::new(vec![]))
        }),
    );

    http_client
}

async fn build_issuer_with_test_did_resolver(
    metadata: IssuerMetadata,
    http_client: impl HttpClient + 'static,
    introspect_ep: Option<Url>,
) -> impl Issuer {
    let kms = LocalKms::new();
    let nonce_gen = LocalNonceHandler::default();
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle_with_test_did_resolver(&kms).await;

    let mut builder = IssuerBuilder::new(kms, metadata, key_metadata)
        .with_nonce_handler(nonce_gen)
        .with_http_client(http_client)
        .with_did_resolver(TestDIDResolver::new(CUSTOM_METHOD_NAME.to_string()))
        .unwrap();

    if let Some(ep) = introspect_ep {
        builder = builder.token_validation_introspect(ep, None);
    }

    builder.build().await.unwrap()
}

async fn create_did_keymetadata_keyhandle_with_test_did_resolver(
    kms: &LocalKms,
) -> (DID, KeyMetadata, KeyHandle) {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = TestDIDResolver::new(CUSTOM_METHOD_NAME.to_string()).generate(kh.clone());

    let mut resolver = UniversalResolver::default();
    resolver
        .add_resolver(TestDIDResolver::new(CUSTOM_METHOD_NAME.to_string()))
        .unwrap();

    let vm = resolver
        .resolve_into_any_verification_method(DIDBuf::from_str(&did).unwrap().as_did())
        .await
        .unwrap()
        .unwrap()
        .id;

    (
        did,
        KeyMetadata {
            kid,
            did_url: vm.to_string(),
        },
        kh,
    )
}

async fn build_holder_with_test_did_resolver(
    credential_offer: CredentialOfferParams,
    http_client: impl HttpClient + 'static,
    kms: LocalKms,
) -> impl Holder {
    let vault = InMemVault::new();

    HolderBuilder::new(
        kms,
        vault,
        "wallet-dev".to_string(),
        IssuerDiscovery::Offer(credential_offer),
    )
    .with_http_client(http_client)
    .with_did_resolver(TestDIDResolver::new(CUSTOM_METHOD_NAME.to_string()))
    .unwrap()
    .build()
    .await
    .unwrap()
}

async fn build_holder_for_oid4vp_with_test_did_resolver(
    http_client: impl HttpClient,
    kms: LocalKms,
    vault: InMemVault,
) -> impl Oid4vpHolder {
    agent_sdk::vc::oid4vp::HolderBuilder::new(kms, vault, "wallet-dev".to_string())
        .with_http_client(http_client)
        .with_did_resolver(TestDIDResolver::new(CUSTOM_METHOD_NAME.to_string()))
        .unwrap()
        .build()
        .await
        .unwrap()
}

async fn create_did_keymetadata_keyhandle_with_custom_did_resolver(
    kms: &LocalKms,
) -> (DID, KeyMetadata, KeyHandle) {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
        .await
        .unwrap();

    let test_resolver = TestDIDResolver::new(CUSTOM_METHOD_NAME.to_string());
    let did = test_resolver.generate(kh.clone());
    let mut resolver = UniversalResolver::default();
    resolver.add_resolver(test_resolver).unwrap();

    let vm = resolver
        .resolve_into_any_verification_method(DIDBuf::from_str(&did).unwrap().as_did())
        .await
        .unwrap()
        .unwrap()
        .id;

    (
        did,
        KeyMetadata {
            kid,
            did_url: vm.to_string(),
        },
        kh,
    )
}

async fn create_vc_with_test_did_resolver(
    format: Oid4VpTestCredentialFormat,
    holder_did_url: &str,
    holder_kid: String,
    holder_kh: impl crypto::Key,
    claims: Claims,
) -> (Credential, CredentialMetadata) {
    println!("claims: {:?}", claims);

    // Generate Issuer DID and Key
    let kms = LocalKms::new();
    let (did, key_metadata, kh) =
        create_did_keymetadata_keyhandle_with_test_did_resolver(&kms).await;
    println!("Issuer DID: {}", did);

    match format {
        Oid4VpTestCredentialFormat::SdJwt(metadata) => {
            let vc = VCFormatsSdJwtAPI::create_vc(
                claims.clone(),
                (DIDURL::new(&key_metadata.did_url).unwrap(), kh),
                (DIDURL::new(holder_did_url).unwrap(), holder_kh),
                metadata,
                UniversalResolver::default(),
            )
            .await
            .unwrap();

            println!("Credential: {}", vc);

            let credential = Credential::SdJwt(vc);
            let metadata = DefaultMetadataProcessor::resolve_metadata(
                &credential,
                KeyMetadata {
                    did_url: holder_did_url.to_string(),
                    kid: holder_kid,
                },
            )
            .unwrap();

            (credential, metadata)
        }
        Oid4VpTestCredentialFormat::LdpVc(metadata) => {
            let mut resolver = UniversalResolver::default();
            resolver
                .add_resolver(TestDIDResolver::new(CUSTOM_METHOD_NAME.to_string()))
                .unwrap();
            let vc = VCFormatsJsonLdAPI::create_vc(
                claims,
                (DIDURL::new(&key_metadata.did_url).unwrap(), kh),
                (DIDURL::new(holder_did_url).unwrap(), holder_kh),
                *metadata,
                resolver,
            )
            .await
            .unwrap();

            println!("Credential: {}", serde_json::to_string_pretty(&vc).unwrap());

            let credential = Credential::LdpVc(vc);
            let metadata = DefaultMetadataProcessor::resolve_metadata(
                &credential,
                KeyMetadata {
                    did_url: holder_did_url.to_string(),
                    kid: holder_kid,
                },
            )
            .unwrap();

            (credential, metadata)
        }
    }
}

async fn build_verifier_with_test_did_resolver() -> impl Verifier {
    let kms = LocalKms::new();
    let nonce_gen = LocalNonceHandler::default();

    let (did, key_metadata, _) =
        create_did_keymetadata_keyhandle_with_custom_did_resolver(&kms).await;
    VerifierBuilder::new(kms, nonce_gen, key_metadata, did)
        .with_client_metadata(default_verifier_metadata())
        .with_did_resolver(TestDIDResolver::new(CUSTOM_METHOD_NAME.to_string()))
        .unwrap()
        .build()
        .await
        .unwrap()
}
pub fn default_verifier_metadata() -> ClientMetadata {
    ClientMetadata::try_from(
        serde_json::from_str::<serde_json::Value>(DEFAULT_CLIENT_METADATA).unwrap(),
    )
    .unwrap()
}

const DEFAULT_CLIENT_METADATA: &str = r#"{
    "vp_formats": {
        "dc+sd-jwt": {
            "alg": [
                "EdDSA",
                "ES256"
            ]
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
