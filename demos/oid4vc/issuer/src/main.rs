use actix_web::http::header::Header;
use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use agent_sdk::did::DID;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::storage::InMemStorage;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::storage::Storage;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vci::{
    AuthorizationCodeGrant, CredDefMetadata, CredDefMetadataProfile, CredentialOfferGrants,
    CredentialRequest, IssuanceSession, IssuerMetadata,
};

use agent_sdk::did::didweb::DIDWeb;
use agent_sdk::did::DIDDoc;
use agent_sdk::inmem::nonce::LocalNonceGenerator;
use agent_sdk::reqwest::ReqwestClient;
use agent_sdk::vc::oid4vci;
use keycloak::{KeycloakAdmin, KeycloakAdminToken};
use reqwest::Url;
use serde_json::{json, Value};
use std::sync::Arc;

const SERVER_URL: &str = "http://localhost:8088";
const AUTH_SRV_URL: &str = "http://localhost:8080/idp/realms/pid-issuer-realm";

const CREDENTIAL_URL_PATH: &str = "/credential";
const METADATA_URL_PATH: &str = "/.well-known/openid-credential-issuer";
const CREDENTIAL_OFFER_URL_PATH: &str = "/credential_offer";
const DID_DOC_URL_PATH: &str = "/.well-known/did.json";

struct AppState {
    issuer: Arc<dyn oid4vci::Issuer>,
    storage: InMemStorage<String, IssuanceSession>,
    did_doc: DIDDoc,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let (issuer, did_document) = issuer().await;

    let app_state = web::Data::new(AppState {
        issuer: Arc::new(issuer),
        storage: InMemStorage::new(),
        did_doc: did_document,
    });
    HttpServer::new(move || {
        App::new()
            .route(CREDENTIAL_URL_PATH, web::post().to(issue_credential))
            .route(METADATA_URL_PATH, web::get().to(issue_metadata))
            .route(CREDENTIAL_OFFER_URL_PATH, web::get().to(credential_offer))
            .route(DID_DOC_URL_PATH, web::get().to(did_doc))
            .app_data(app_state.clone())
    })
    .bind(("127.0.0.1", 8088))?
    .run()
    .await
}

async fn issue_credential(
    state: web::Data<AppState>,
    req: HttpRequest,
    cred_req: web::Json<CredentialRequest>,
) -> Result<HttpResponse, Error> {
    let token = Authorization::<Bearer>::parse(&req)?
        .into_scheme()
        .token()
        .to_owned();

    let cred_def = state.issuer.get_cred_def_metadata(&cred_req).unwrap();

    // Depending on the concrete `CredDef` requested Claims would be different
    let claims = get_user_attributes(&cred_def).await?;

    let mut session = state
        .storage
        .get(&token)
        .await
        .unwrap()
        .unwrap_or(IssuanceSession::default());

    let resp = state
        .issuer
        .issue_credential(&cred_req, &token, &claims, &mut session)
        .await;

    state.storage.put(token, session).await.unwrap();

    println!("Issuance Result: {:?}", resp);

    match resp {
        Ok(body) => Ok(HttpResponse::Ok().json(body)),
        // Protocol errors are expected
        Err(oid4vci::Error::Protocol { source }) => Ok(HttpResponse::BadRequest().json(source)),
        Err(_) => Ok(HttpResponse::InternalServerError().json(json!({}))),
    }
}

async fn issue_metadata(state: web::Data<AppState>) -> HttpResponse {
    let metadata = state.issuer.get_issuer_metadata();

    HttpResponse::Ok().json(serde_json::to_value(metadata).unwrap())
}

async fn credential_offer(state: web::Data<AppState>) -> HttpResponse {
    let (credential_offer, url) = state
        .issuer
        .create_credential_offer(
            vec!["SD_JWT_cred_1", "SD_JWT_cred_2"],
            &CredentialOfferGrants {
                authorization_code: Some(AuthorizationCodeGrant { issuer_state: None }),
                pre_authorized_code: None,
            },
        )
        .unwrap();

    println!("Offer {:?}", credential_offer);
    println!("URL {}", url);

    HttpResponse::Ok().json(credential_offer)
}

async fn did_doc(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok().json(state.did_doc.clone())
}

async fn get_user_attributes(cred_def: &CredDefMetadata) -> Result<Value, Error> {
    let vct = match cred_def.additional_fields() {
        CredDefMetadataProfile::SDJWTVC(m) => m.vct(),
        _ => panic!("only sd-jwt supported in demo"),
    };

    // Issue dummy VC for SD_JWT_cred_2
    // Just to demonstrate, that claims and values should be different between creds
    if vct == "https://credentials.example.com/identity_credential_2" {
        let mut claims_json = json!({});
        claims_json["username"] = serde_json::Value::from("USER");
        claims_json["email"] = serde_json::Value::from("HARDCODED@gmail.com");
        return Ok(claims_json);
    }

    let (realm_name, user_name, keycloak_url) = (
        "pid-issuer-realm".to_owned(),
        "tneal".to_owned(),
        "http://localhost:8080/idp",
    );

    let client = reqwest::Client::builder()
        .https_only(false)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let admin_token = KeycloakAdminToken::acquire_custom_realm(
        keycloak_url,
        "admin",
        "password",
        "master",
        "admin-cli",
        "password",
        &client,
    )
    .await
    .unwrap();

    let keycloak_admin = KeycloakAdmin::new(keycloak_url, admin_token, client);

    let users = keycloak_admin
        .realm_users_get(
            &realm_name,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(user_name),
        )
        .await
        .unwrap();

    if let Some(user) = users.first().cloned() {
        let mut claims_json = serde_json::to_value(user.attributes).unwrap();
        claims_json["family_name"] = serde_json::Value::from(user.last_name.to_owned());
        claims_json["given_name"] = serde_json::Value::from(user.first_name.to_owned());
        claims_json["username"] = serde_json::Value::from(user.username.to_owned());
        claims_json["email"] = serde_json::Value::from(user.email.to_owned());
        return Ok(claims_json);
    }

    Ok(Value::Null)
}

async fn issuer() -> (impl oid4vci::Issuer, DIDDoc) {
    println!("Initializing issuer...");
    let kms = LocalKms::new();
    let nonce_gen = LocalNonceGenerator::default();
    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (_, key_metadata, did_doc) = create_did_and_key_metadata(&kms).await;

    let issuer_metadata = sample_issuer_metadata(SERVER_URL, AUTH_SRV_URL);

    let issuer = oid4vci::IssuerBuilder::new(kms, nonce_gen, issuer_metadata, key_metadata)
        .with_http_client(ReqwestClient::unsecure().unwrap())
        .token_validation_introspect(
            Url::parse("http://localhost:8080/idp/realms/pid-issuer-realm/protocol/openid-connect/token/introspect").unwrap(),
            Some(format!("Basic {}", "cGlkLWlzc3Vlci1zcnY6eklLQVY5RElJSWFKQ3pIQ1ZCUGx5U2dVOEtnWTY4VTI=")),
        )
        .build().await.unwrap();

    println!("Done");
    (issuer, did_doc)
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata, DIDDoc) {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = DIDWeb::generate_did_from_url(SERVER_URL).unwrap();
    let did_doc = DIDWeb::generate_did_document(&did, &kh).unwrap();
    let vm = format!("{did}#key-0");

    println!("Generated DID {}", did.clone());
    println!("Generated DIDURL {}", vm.clone());

    (did, KeyMetadata { kid, did_url: vm }, did_doc)
}

const CRED_DEF_1: &str = "SD_JWT_cred_1";
const CRED_DEF_2: &str = "SD_JWT_cred_2";

fn sample_issuer_metadata(iss_url: &str, authz_url: &str) -> IssuerMetadata {
    let metadata = serde_json::from_value(json!(
        {
          "credential_issuer": iss_url,
          "authorization_servers": [authz_url],
          "credential_endpoint": iss_url.to_owned()+"/credential",
          "credential_configurations_supported": {
            CRED_DEF_1: {
              "format": "vc+sd-jwt",
              "scope": "SD_JWT_cred_scope",
              "cryptographic_binding_methods_supported": [
                "jwk"
              ],
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "vct": "https://credentials.example.com/identity_credential_1",
              "claims": {
                "given_name": {},
                "age_over_18": {},
                "street": {},
                "email": {},
                "username": {},
                "postal_code": {},
                "locality": {},
                "region": {},
                "birthdate": {},
                "gender": {},
                "country": {},
                "family_name": {}
              }
            },
            CRED_DEF_2: {
              "format": "vc+sd-jwt",
              "scope": "SD_JWT_cred_scope",
              "cryptographic_binding_methods_supported": [
                "jwk"
              ],
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "vct": "https://credentials.example.com/identity_credential_2",
              "claims": {
                "email": {},
                "username": {},
              }
            }
          }
        }
    ));

    metadata.unwrap()
}
