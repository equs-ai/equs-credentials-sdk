#![allow(dead_code)]

mod utils;

use futures::executor;
use oauth2::http::header::CONTENT_TYPE;
use oauth2::http::{HeaderValue, Method};
use oauth2::HttpResponse;
use rstest::rstest;
use std::collections::HashMap;
use url::Url;
use utils::fixtures::oid4vp::Oid4VpTestCredentialFormat;

use agent_sdk::crypto;
use agent_sdk::http::HttpClient;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::vault::Vault;
use agent_sdk::vc::oid4vp::{
    AuthResponseOptions, AuthorizationResponseMetadata, ClientMetadata, IdTokenMetadata,
    PassAuthRequestObject, ResponseMode, ResponseType,
};
use agent_sdk::vc::oid4vp::{AuthorizationResponse, Holder};
use agent_sdk::vc::oid4vp::{HolderBuilder, PresentationSession};
use agent_sdk::vc::oid4vp::{Verifier, VerifierBuilder};
use agent_sdk::vc::VCFormatsAPI;
use agent_sdk::vc::{Credential, CredentialMetadata};
use agent_sdk::vc::{VCFormatsJsonLdAPI, VCFormatsSdJwtAPI};

use utils::helpers::create_did_keymetadata_keyhandle;
use utils::http::HttpClientEmulator;

use crate::utils::fixtures::oid4vp::{
    multiple_sdjwt_presentation_case, single_jsonld_presentation_case,
    single_sdjwt_presentation_case, Oid4VpTestCase, ValidateClaimsFunc, STATE, VERIFIER_URL,
};
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::DIDURL;
use agent_sdk::inmem::kms::KeyHandle;
use agent_sdk::inmem::nonce::LocalNonceHandler;
use agent_sdk::vc::claims::Claims;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};

#[rstest]
#[case::single_jsonld_presentation(single_jsonld_presentation_case())]
#[case::single_sdjwt_presentation(single_sdjwt_presentation_case())]
#[case::multiple_sdjwt_presentation(multiple_sdjwt_presentation_case())]
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

    let http_client = prepare_http_client_for_holder(
        session.auth_request_jwt.clone().unwrap(),
        verifier,
        test_case.validate,
        session,
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

fn prepare_http_client_for_holder(
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
    HolderBuilder::new(kms, vault, "wallet-dev".to_string())
        .with_http_client(http_client)
        .build()
        .await
        .unwrap()
}

async fn create_vc(
    format: Oid4VpTestCredentialFormat,
    holder_did_url: &str,
    holder_kid: String,
    holder_kh: impl crypto::Key,
    claims: Claims,
) -> (Credential, CredentialMetadata) {
    println!("claims: {:?}", claims);

    // Generate Issuer DID and Key
    let kms = LocalKms::new();
    let (did, key_metadata, kh) = create_did_keymetadata_keyhandle(&kms).await;
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
            let vc = VCFormatsJsonLdAPI::create_vc(
                claims,
                (DIDURL::new(&key_metadata.did_url).unwrap(), kh),
                (DIDURL::new(holder_did_url).unwrap(), holder_kh),
                *metadata,
                UniversalResolver::default(),
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

pub async fn generate_did_key_and_vm(kms: &LocalKms) -> (KeyMetadata, KeyHandle) {
    let (_, key_md, key_handle) = create_did_keymetadata_keyhandle(kms).await;

    (key_md, key_handle)
}

fn default_verifier_metadata() -> ClientMetadata {
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
