use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::{DIDBuf, DIDResolver, DID};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::storage::InMemStorage;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::storage::Storage;
use agent_sdk::vc::core::KeyMetadata;

use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::inmem::nonce::LocalNonceGenerator;
use agent_sdk::vc::oid4vp;
use agent_sdk::vc::oid4vp::{
    AuthResponseOptions, AuthorizationResponse, ClientMetadata, PassAuthRequestObject,
    PresentationSession, ResponseMode, ResponseType,
};
use agent_sdk::vc::presentation_exchange::{
    ClaimFormatDesignation, ClaimFormatMap, ClaimFormatPayload, Constraints, ConstraintsField,
    InputDescriptor, JsonPath, PresentationDefinition,
};
use reqwest::Url;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

const SERVER_URL: &str = "http://localhost:8098";
const AUTH_REQUEST_URL_PATH: &str = "/request_uri";
const AUTH_REQUEST_OBJECT_URL_PATH: &str = "/request";
const AUTH_RESPONSE_URL_PATH: &str = "/present";

struct AppState {
    verifier: Arc<dyn oid4vp::Verifier>,
    auth_req_obj_storage: InMemStorage<String, Option<String>>,
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

    let auth_resp_config = AuthResponseOptions {
        type_: ResponseType::VpTokenIdToken,
        mode: ResponseMode::DirectPost,
        submission_uri: response_uri,
    };

    let pass_auth_req_object = PassAuthRequestObject::ByReference(request_uri.clone());

    let (auth_req, session) = state
        .verifier
        .create_authorization_request(
            &default_presentation_definition(),
            &auth_resp_config,
            &pass_auth_req_object,
            None,
        )
        .await
        .unwrap();

    state
        .auth_req_obj_storage
        .put(request_uri.to_string(), session.auth_request_jwt.to_owned())
        .await
        .unwrap();

    state
        .presentation_session_storage
        .put(session.presentation_definition.id().to_owned(), session)
        .await
        .unwrap();

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(auth_req.to_string())
}

async fn presentation_response(
    state: web::Data<AppState>,
    req: web::Form<HashMap<String, String>>,
) -> HttpResponse {
    if req.contains_key("error") {
        println!(
            "Received authorization error response: error = {}, error_description = {}",
            req.0.get("error").unwrap(),
            req.0.get("error_description").unwrap_or(&"".to_string())
        );

        return HttpResponse::Ok().finish();
    }

    let wallet_auth_resp = auth_resp_from_submitted_form(&req);

    let session = state
        .presentation_session_storage
        .get(wallet_auth_resp.presentation_submission.definition_id())
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
        serde_json::to_string_pretty(&verified_claims).unwrap()
    );

    HttpResponse::Ok().finish()
}

fn auth_resp_from_submitted_form(
    form: &web::Form<HashMap<String, String>>,
) -> AuthorizationResponse {
    let vp_token_str = form.get("vp_token").unwrap();
    let vp_token =
        serde_json::from_str(vp_token_str).unwrap_or(serde_json::to_value(vp_token_str).unwrap());
    let presentation_submission =
        serde_json::from_str(form.get("presentation_submission").unwrap()).unwrap();
    let id_token = form.get("id_token").cloned();

    AuthorizationResponse {
        vp_token,
        presentation_submission,
        id_token,
    }
}

async fn verifier() -> impl oid4vp::Verifier {
    println!("Initializing verifier...");
    let kms = LocalKms::new();
    let nonce_gen = LocalNonceGenerator::default();
    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

    let verifier = oid4vp::VerifierBuilder::new(kms, nonce_gen, key_metadata, did)
        .with_client_metadata(default_verifier_metadata())
        .build()
        .await
        .unwrap();

    println!("Done");
    verifier
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = DIDKey::generate(kh).unwrap();

    let did_url = UniversalResolver::default()
        .resolve(DIDBuf::from_str(&did).unwrap().as_did())
        .await
        .unwrap()
        .document
        .verification_method
        .first()
        .unwrap()
        .id
        .to_string();

    println!("Generated DID {}", did);
    println!("Generated DIDURL {}", did_url);

    (did, KeyMetadata { kid, did_url })
}

pub fn default_presentation_definition() -> PresentationDefinition {
    let vct_filter = json!({
        "type": "string",
        "const": "https://credentials.example.com/identity_credential_1"
    });
    let vct_constraint = ConstraintsField::new(JsonPath::parse("$.vct").unwrap())
        .set_filter(&vct_filter)
        .unwrap();

    let email_constraint = ConstraintsField::new(JsonPath::parse("$.email.work").unwrap());

    let username_constraint =
        ConstraintsField::new(JsonPath::parse("$.username").unwrap()).set_optional(true);

    let country_filter = json!({
        "type": "string",
        "const": "US"
    });
    let country_constraint = ConstraintsField::new(JsonPath::parse("$.country").unwrap())
        .set_filter(&country_filter)
        .unwrap();

    let constraints = Constraints::new()
        .add_constraint(vct_constraint)
        .add_constraint(email_constraint)
        .add_constraint(username_constraint)
        .add_constraint(country_constraint);

    let mut format = ClaimFormatMap::new();
    format.insert(
        ClaimFormatDesignation::SdJwtVc,
        ClaimFormatPayload::Json(json!({
          "sd-jwt_alg_values": ["ES256", "EdDSA"],
          "kb-jwt_alg_values": ["ES256", "EdDSA"]
        })),
    );

    let input_descriptor_1 = InputDescriptor::new("Identity-1".to_string(), constraints)
        .set_name("Identity VC".to_string())
        .set_purpose("We want an identity".to_string())
        .set_format(format);

    PresentationDefinition::new(Uuid::new_v4().to_string(), input_descriptor_1)
        .add_input_descriptor(serde_json::from_str(INPUT_DESCRIPTOR_FOR_CRED_DEF_2).unwrap())
        .set_name("Example with selective disclosure".to_owned())
}

const INPUT_DESCRIPTOR_FOR_CRED_DEF_2: &str = r#"{
    "id": "resident-card",
    "name": "Identity VC",
    "purpose": "We want a resident card",
    "format": {
        "ldp_vc": {
           "proof_type": [
            "Ed25519Signature2018",
            "EcdsaSecp256k1Signature2019"
           ]
        }
    },
    "constraints": {
        "fields": [
            {
                "path": ["$.type"],
                "filter": {
                    "type": "array",
                    "contains": {
                        "const": "PermanentResidentCard"
                    }
                }
            }
        ]
    }
}"#;

fn default_verifier_metadata() -> ClientMetadata {
    ClientMetadata::try_from(
        serde_json::from_str::<serde_json::Value>(DEFAULT_CLIENT_METADATA).unwrap(),
    )
    .unwrap()
}

const DEFAULT_CLIENT_METADATA: &str = r#"{
    "vp_formats": {
        "vc+sd-jwt": {
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
