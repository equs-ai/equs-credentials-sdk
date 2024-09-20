#![allow(dead_code)]

mod utils;

use futures::executor;
use oauth2::http::header::CONTENT_TYPE;
use oauth2::http::{HeaderMap, HeaderValue, Method, StatusCode};
use oauth2::HttpResponse;
use rstest::rstest;
use ssi::did::DIDURL;
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;

use agent_sdk::crypto;
use agent_sdk::crypto::Alg;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::http::HttpClient;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::vault::Vault;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vp::{
    auth_request_as_url, AuthorizationResponseMetadata, AuthorizationUrlType,
};
use agent_sdk::vc::oid4vp::{AuthorizationResponse, Holder};
use agent_sdk::vc::oid4vp::{HolderBuilder, PresentationSession};
use agent_sdk::vc::oid4vp::{Verifier, VerifierBuilder};
use agent_sdk::vc::VCFormatsAPI;
use agent_sdk::vc::{Credential, CredentialMetadata, VCFormat};
use agent_sdk::vc::{VCFormatsSdJwtAPI, VCMetadata};

use utils::helpers::create_did_keymetadata_keyhandle;
use utils::http::HttpClientEmulator;

use agent_sdk::did::{DIDResolver, DID};
use agent_sdk::inmem::kms::KeyHandle;
use agent_sdk::kms::KeyID;

use crate::utils::fixtures::oid4vp::{
    multiple_presentation_case, single_presentation_case, Oid4VpTestCase, ValidateClaimsFunc,
    VERIFIER_URL,
};

#[rstest]
#[case::single_presentation(single_presentation_case())]
#[case::multiple_presentation(multiple_presentation_case())]
#[tokio::test]
async fn credentials_presentation_and_verification(#[case] test_case: Oid4VpTestCase) {
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

    // Create Verifier
    let verifier = build_verifier().await;

    println!("8.1 Verifier: Create Authorization Request");
    // TODO: We should not use a test constant for Presentation Definition here,
    //  we need to build a new one (as every Verifier will build it).
    let nonce = "n0NcE".into();
    let response_uri: Url = format!("{}/auth", VERIFIER_URL).parse().unwrap();
    let (auth_request, session) = verifier
        .create_authorization_request(&test_case.presentation_definition, &nonce, response_uri)
        .await
        .unwrap();

    let by_reference = auth_request_as_url(
        &auth_request,
        AuthorizationUrlType::Reference(format!("{}/request", &VERIFIER_URL).parse().unwrap()),
    );

    let http_client = prepare_http_client_for_holder(
        auth_request.request_object_jwt.clone(),
        verifier,
        test_case.validate,
        session,
    );

    // Create Holder
    let holder = build_holder(
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
            assert_eq!(req.method, Method::GET);

            let resp = HttpResponse {
                status_code: StatusCode::OK,
                headers: HeaderMap::from_iter(vec![(
                    CONTENT_TYPE,
                    HeaderValue::from_str("text/plain").unwrap(),
                )]),
                body: Vec::from(request_object_jwt.to_owned()),
            };

            Ok(resp)
        }),
    );

    http_client.add_handler(
        Url::parse(VERIFIER_URL).unwrap().join("/auth").unwrap(),
        Box::new(move |req| {
            assert_eq!(req.method, Method::POST);

            println!("10. Verify Presentation");
            let form: HashMap<String, String> =
                serde_urlencoded::from_bytes(req.body.as_slice()).unwrap();
            // Retrieve vp_token and presentation_definition from submitted form
            let vp_token = serde_json::from_str(form.get("vp_token").unwrap().as_str()).unwrap();
            let presentation_submission =
                serde_json::from_str(form.get("presentation_submission").unwrap().as_str())
                    .unwrap();

            let auth_response = AuthorizationResponse {
                vp_token,
                presentation_submission,
            };

            let result = executor::block_on(verifier.verify_presentation(&auth_response, &session));
            let claims = result.unwrap();
            println!("Presentation Claims: {}", claims);

            validate_claims_func(claims);

            Ok(HttpResponse {
                status_code: StatusCode::OK,
                headers: Default::default(),
                body: vec![],
            })
        }),
    );

    http_client
}

async fn build_verifier() -> impl Verifier {
    let kms = LocalKms::new();

    let (did, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;

    VerifierBuilder::new(kms, key_metadata, did)
        .build()
        .await
        .unwrap()
}

async fn build_holder(
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
    claims: serde_json::Value,
) -> (Credential, CredentialMetadata) {
    // Generate Issuer DID and Key
    let kms = LocalKms::new();
    let (did, _, kh) = create_did_keymetadata_keyhandle(&kms).await;

    println!("Issuer DID: {}", did);

    let did_url = DIDURL::from_str(&did).unwrap();

    let vc = VCFormatsSdJwtAPI::create_vc(
        VCFormatsSdJwtAPI::resolve_claims(&claims),
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

pub async fn generate_did_key_and_vm(
    kms: &LocalKms,
    did_resolver: &UniversalResolver,
) -> (KeyID, KeyHandle, DID, String) {
    let (did, key_md, key_handle) = create_did_keymetadata_keyhandle(kms).await;

    let vm_id = did_resolver
        .resolve_verification_method(&did)
        .await
        .unwrap()
        .id;

    (key_md.kid, key_handle, did, vm_id)
}
