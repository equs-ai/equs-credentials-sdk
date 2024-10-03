use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::{DIDResolver, DID};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::storage::InMemStorage;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::storage::Storage;
use agent_sdk::vc::core::KeyMetadata;

use agent_sdk::inmem::nonce::LocalNonceGenerator;
use agent_sdk::vc::oid4vp::{
    auth_request_as_url, AuthorizationResponse, AuthorizationUrlType, PresentationDefinition,
    PresentationSession,
};
use agent_sdk::vc::{oid4vp, DefaultPresentationBuilder, PresentationBuilder};
use reqwest::Url;
use std::collections::HashMap;
use std::sync::Arc;

const SERVER_URL: &str = "http://localhost:8098";
const AUTH_REQUEST_URL_PATH: &str = "/request_uri";
const AUTH_REQUEST_OBJECT_URL_PATH: &str = "/request";
const AUTH_RESPONSE_URL_PATH: &str = "/present";

struct AppState {
    verifier: Arc<dyn oid4vp::Verifier>,
    auth_req_obj_storage: InMemStorage<String, String>,
    presentation_session_storage: InMemStorage<String, PresentationSession>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let app_state = web::Data::new(AppState {
        verifier: Arc::new(verifier().await),
        auth_req_obj_storage: InMemStorage::new(),
        presentation_session_storage: InMemStorage::new(),
    });
    HttpServer::new(move || {
        App::new()
            .route(
                AUTH_REQUEST_URL_PATH,
                web::get().to(presentation_request_uri),
            )
            .route(
                AUTH_REQUEST_OBJECT_URL_PATH,
                web::get().to(presentation_request_object),
            )
            .route(
                AUTH_RESPONSE_URL_PATH,
                web::post().to(presentation_response),
            )
            .app_data(app_state.clone())
    })
    .bind(("127.0.0.1", 8098))?
    .run()
    .await
}

async fn presentation_request_object(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
    let auth_req_object = state
        .auth_req_obj_storage
        .get(&req.full_url().to_string())
        .await
        .unwrap()
        .unwrap();

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(auth_req_object)
}

async fn presentation_request_uri(state: web::Data<AppState>) -> HttpResponse {
    let response_uri =
        Url::parse(format!("{}{}", SERVER_URL, AUTH_RESPONSE_URL_PATH).as_str()).unwrap();
    let request_uri =
        Url::parse(format!("{}{}", SERVER_URL, AUTH_REQUEST_OBJECT_URL_PATH).as_str()).unwrap();

    // Verifier may build a custom presentation definition depending on the needs of verification
    let (auth_req, session) = state
        .verifier
        .create_authorization_request(&default_presentation_definition(), response_uri)
        .await
        .unwrap();

    let url = auth_request_as_url(
        &auth_req,
        AuthorizationUrlType::Reference(request_uri.clone()),
    )
    .to_string();

    state
        .auth_req_obj_storage
        .put(request_uri.to_string(), auth_req.request_object_jwt)
        .await
        .unwrap();

    state
        .presentation_session_storage
        .put(session.presentation_definition.id.clone(), session)
        .await
        .unwrap();

    HttpResponse::Ok().content_type("text/plain").body(url)
}

async fn presentation_response(
    state: web::Data<AppState>,
    req: web::Form<HashMap<String, String>>,
) -> HttpResponse {
    let wallet_auth_resp = auth_resp_from_submitted_form(&req);

    let session = state
        .presentation_session_storage
        .get(&wallet_auth_resp.presentation_submission.definition_id)
        .await
        .unwrap()
        .unwrap();

    let verified_claims = state
        .verifier
        .verify_presentation(&wallet_auth_resp, &session)
        .await
        .unwrap();

    println!(
        "Verifier claims: {}",
        serde_json::to_string(&verified_claims).unwrap()
    );

    HttpResponse::Ok().finish()
}

fn auth_resp_from_submitted_form(
    form: &web::Form<HashMap<String, String>>,
) -> AuthorizationResponse {
    let vp_token = serde_json::from_str(form.get("vp_token").unwrap()).unwrap();
    let presentation_submission =
        serde_json::from_str(form.get("presentation_submission").unwrap()).unwrap();

    AuthorizationResponse {
        vp_token,
        presentation_submission,
    }
}

async fn verifier() -> impl oid4vp::Verifier {
    println!("Initializing verifier...");
    let kms = LocalKms::new();
    let nonce_gen = LocalNonceGenerator::default();
    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

    let verifier = oid4vp::VerifierBuilder::new(kms, nonce_gen, key_metadata, did)
        .build()
        .await
        .unwrap();

    println!("Done");
    verifier
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    let didkey = DIDKey::new();

    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = didkey.generate(kh).unwrap();

    let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

    println!("Generated DID {}", did.clone());
    println!("Generated DIDURL {}", vm.clone());

    (did, KeyMetadata { kid, did_url: vm })
}

pub fn default_presentation_definition() -> PresentationDefinition {
    let builder = DefaultPresentationBuilder::default()
        .with_name("Example with selective disclosure")
        .with_input_descriptor(&serde_json::from_str(INPUT_DESCRIPTOR_FOR_CRED_DEF_1).unwrap())
        .with_input_descriptor(&serde_json::from_str(INPUT_DESCRIPTOR_FOR_CRED_DEF_2).unwrap())
        .build();

    builder.unwrap().parsed().to_owned()
}

const INPUT_DESCRIPTOR_FOR_CRED_DEF_1: &str = r#"{
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
                    "$.family_name",
                    "$.given_name"
                ]
            },
            {
                "path": ["$.vct"],
                "filter": {
                    "type": "string",
                    "const": "https://credentials.example.com/identity_credential_1"
                }
            }
        ]
    }
}"#;

const INPUT_DESCRIPTOR_FOR_CRED_DEF_2: &str = r#"{
    "id": "Identity-2",
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
                    "$.email",
                    "$.username"
                ]
            },
            {
                "path": ["$.vct"],
                "filter": {
                    "type": "string",
                    "const": "https://credentials.example.com/identity_credential_2"
                }
            }
        ]
    }
}"#;
