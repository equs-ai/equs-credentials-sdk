#![allow(dead_code)]

mod utils;

use agent_sdk::http::HttpClient;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::vc::oid4vci;
use agent_sdk::vc::oid4vci::{CredentialOfferGrants, Holder, IssuanceSession, Issuer};
use async_mutex::Mutex;
use futures::executor;
use oauth2::http::Method;
use oauth2::http::StatusCode;
use oauth2::{HttpRequest, HttpResponse, TokenResponse};
use oid4vci::AuthorizationCodeGrant;
use rstest::rstest;
use serde_json::json;
use std::borrow::{Borrow, BorrowMut};
use std::sync::Arc;
use std::{io, str};
use utils::http::HttpClientEmulator;
use uuid::Uuid;

use utils::fixtures::{
    sample_authz_url, sample_claims_jsonld, sample_claims_sdjwt, sample_issuer_metadata,
    sample_issuer_url, ACCESS_TOKEN, AUTHZ_URL, SCOPE,
};

use crate::utils::helpers::create_did_keymetadata_keyhandle;
use utils::helpers::oid4vci::{build_holder, build_issuer, setup_http_static_handlers};

#[rstest]
#[case::token_validation_enabled(true)]
#[case::token_validation_disabled(false)]
#[tokio::test]
async fn autorized_code_flow_using_scopes(#[case] validate_token: bool) {
    // Setting up mocks and fixtures
    let issuer_metadata = sample_issuer_metadata();

    let authz_code = Uuid::new_v4().to_string();
    let req_uri_code = Uuid::new_v4().to_string();
    let mut introspect_ep = None;

    if validate_token {
        introspect_ep = Some(sample_authz_url().join("/token/introspect").unwrap());
    }

    // 1. Creating issuer from issuer metadata
    let issuer = build_issuer(
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
    let holder = build_holder(offer, http_client_for_holder, kms.clone()).await;

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
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;
    let response = holder
        .request_credential(
            token_response.access_token(),
            "SD_JWT_cred_1",
            None,
            &key_metadata,
        )
        .await
        .unwrap();

    println!("Credential 1: {:?}", response.data);

    // Extra check that subsequent nonce returned
    let nonce_data = response.nonce_data;
    assert!(nonce_data.is_some());

    // 6.2 Holder requests LDPVC_cred_1 credentials with the same token
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;
    let response = holder
        .request_credential(
            token_response.access_token(),
            "LDPVC_cred_1",
            nonce_data.as_ref(),
            &key_metadata,
        )
        .await
        .unwrap();

    match response.data {
        oid4vci::CredentialResult::Credential { credential, .. } => {
            println!(
                "Credential 2: {}",
                serde_json::to_string_pretty(&credential).unwrap()
            );
        }
        _ => panic!("unexpected result"),
    }
}

async fn credential_endpoint(
    issuer: &impl Issuer,
    req: HttpRequest,
    session: Arc<Mutex<IssuanceSession>>,
) -> HttpResponse {
    let cred_req_str = std::str::from_utf8(req.body().as_slice()).unwrap();

    let claims = if cred_req_str.contains("\"vc+sd-jwt\"") {
        sample_claims_sdjwt()
    } else if cred_req_str.contains("\"ldp_vc\"") {
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

    let mut session_lock = session.lock().await;

    let result = issuer
        .issue_credential(&cred_req, &token, &claims, session_lock.borrow_mut())
        .await;

    assert!(session_lock.borrow().nonce.is_some());

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

    let session = Arc::new(Mutex::new(IssuanceSession::default()));
    http_client.add_handler(
        sample_issuer_url().join("/credential").unwrap(),
        Box::new(move |req| {
            let fut = credential_endpoint(&issuer, req, Arc::clone(&session));
            let result = executor::block_on(fut); // TODO: get rid of `block_on` here
            Ok(result)
        }),
    );

    http_client
}
