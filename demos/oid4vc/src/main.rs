use actix_web::http::header::Header;
use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::{DIDResolver, DID};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::storage::InMemStorage;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::storage::Storage;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vci::{
    AuthorizationCodeGrant, CredDefMetadata, CredDefMetadataProfile, CredentialOffer,
    CredentialOfferGrants, CredentialRequest, IssuanceSession, IssuerMetadata,
};
use agent_sdk::vc::oid4vp::{
    auth_request_as_url, AuthorizationResponse, AuthorizationUrlType, Nonce,
    PresentationDefinition, PresentationSession,
};
use agent_sdk::vc::{oid4vci, oid4vp};
use keycloak::{KeycloakAdmin, KeycloakAdminToken};
use reqwest::Url;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

const SERVER_URL: &str = "http://localhost:8088";
const AUTH_SRV_URL: &str = "http://localhost:8080/idp/realms/pid-issuer-realm";

const OID4VCI_ISSUE_CREDENTIAL_URL_PATH: &str = "/credential";
const OID4VCI_ISSUER_METADATA_URL_PATH: &str = "/.well-known/openid-credential-issuer";
const OID4VCI_CREDENTIAL_OFFER_URL_PATH: &str = "/credential_offer";
const OID4VP_AUTH_REQUEST_URL_PATH: &str = "/request_uri";
const OID4VP_AUTH_REQUEST_OBJECT_URL_PATH: &str = "/request";
const OID4VP_AUTH_RESPONSE_URL_PATH: &str = "/present";

struct AppState {
    issuer: Arc<dyn oid4vci::Issuer>,
    verifier: Arc<dyn oid4vp::Verifier>,
    issuer_storage: InMemStorage<String, IssuanceSession>,
    verifier_auth_req_obj_storage: InMemStorage<String, String>,
    verifier_presentation_session_storage: InMemStorage<String, PresentationSession>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let app_state = web::Data::new(AppState {
        issuer: Arc::new(oid4vci_issuer().await),
        verifier: Arc::new(oid4vp_verifier().await),
        issuer_storage: InMemStorage::new(),
        verifier_auth_req_obj_storage: InMemStorage::new(),
        verifier_presentation_session_storage: InMemStorage::new(),
    });
    HttpServer::new(move || {
        App::new()
            .route(
                OID4VCI_ISSUE_CREDENTIAL_URL_PATH,
                web::post().to(oid4vci_issue_credential),
            )
            .route(
                OID4VCI_ISSUER_METADATA_URL_PATH,
                web::get().to(oid4vci_issue_metadata),
            )
            .route(
                OID4VCI_CREDENTIAL_OFFER_URL_PATH,
                web::get().to(oid4vci_credential_offer),
            )
            .route(
                OID4VP_AUTH_REQUEST_URL_PATH,
                web::get().to(oid4vp_presentation_request_uri),
            )
            .route(
                OID4VP_AUTH_REQUEST_OBJECT_URL_PATH,
                web::get().to(oid4vp_presentation_request_object),
            )
            .route(
                OID4VP_AUTH_RESPONSE_URL_PATH,
                web::post().to(oid4vp_presentation_response),
            )
            .app_data(app_state.clone())
    })
    .bind(("127.0.0.1", 8088))?
    .run()
    .await
}

async fn oid4vci_issue_credential(
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
        .issuer_storage
        .get(&token)
        .await
        .unwrap()
        .unwrap_or(IssuanceSession::default());

    let resp = state
        .issuer
        .issue_credential(&cred_req, &token, &claims, &mut session)
        .await;

    state.issuer_storage.put(token, session).await.unwrap();

    println!("Issuance Result: {:?}", resp);

    match resp {
        Ok(body) => Ok(HttpResponse::Ok().json(body)),
        // Protocol errors are expected
        Err(oid4vci::Error::Protocol { source }) => Ok(HttpResponse::BadRequest().json(source)),
        Err(_) => Ok(HttpResponse::InternalServerError().json(json!({}))),
    }
}

async fn oid4vci_issue_metadata(state: web::Data<AppState>) -> HttpResponse {
    let metadata = state.issuer.get_issuer_metadata();

    HttpResponse::Ok().json(serde_json::to_value(metadata).unwrap())
}

async fn oid4vci_credential_offer(state: web::Data<AppState>) -> HttpResponse {
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

    HttpResponse::Ok().json(CredentialOffer::Value { credential_offer })
}

async fn oid4vp_presentation_request_object(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let auth_req_object = state
        .verifier_auth_req_obj_storage
        .get(&req.full_url().to_string())
        .await
        .unwrap()
        .unwrap();

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(auth_req_object)
}

async fn oid4vp_presentation_request_uri(state: web::Data<AppState>) -> HttpResponse {
    let response_uri =
        Url::parse(format!("{}{}", SERVER_URL, OID4VP_AUTH_RESPONSE_URL_PATH).as_str()).unwrap();
    let request_uri =
        Url::parse(format!("{}{}", SERVER_URL, OID4VP_AUTH_REQUEST_OBJECT_URL_PATH).as_str())
            .unwrap();

    // Verifier may build a custom presentation definition depending on the needs of verification
    let (auth_req, session) = state
        .verifier
        .create_authorization_request(
            &default_presentation_definition(),
            &Nonce::from("nOnCe"),
            response_uri,
        )
        .await
        .unwrap();

    let url = auth_request_as_url(
        &auth_req,
        AuthorizationUrlType::Reference(request_uri.clone()),
    )
    .to_string();

    state
        .verifier_auth_req_obj_storage
        .put(request_uri.to_string(), auth_req.request_object_jwt)
        .await
        .unwrap();

    state
        .verifier_presentation_session_storage
        .put(session.presentation_definition.id.clone(), session)
        .await
        .unwrap();

    HttpResponse::Ok().content_type("text/plain").body(url)
}

async fn oid4vp_presentation_response(
    state: web::Data<AppState>,
    req: web::Form<HashMap<String, String>>,
) -> HttpResponse {
    let wallet_auth_resp = oid4vp_auth_resp_from_submitted_form(&req);

    let session = state
        .verifier_presentation_session_storage
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

fn oid4vp_auth_resp_from_submitted_form(
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

async fn oid4vci_issuer() -> impl oid4vci::Issuer {
    println!("Initializing oid4vci issuer...");
    let kms = LocalKms::new();
    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

    let issuer_metadata = sample_issuer_metadata(SERVER_URL, AUTH_SRV_URL);

    let issuer = oid4vci::IssuerBuilder::new(kms, issuer_metadata, key_metadata)
        .token_validation_introspect(
            Url::parse("http://localhost:8080/idp/realms/pid-issuer-realm/protocol/openid-connect/token/introspect").unwrap(),
            Some(format!("Basic {}", "cGlkLWlzc3Vlci1zcnY6eklLQVY5RElJSWFKQ3pIQ1ZCUGx5U2dVOEtnWTY4VTI=")),
        )
        .build().await.unwrap();

    println!("Done");
    issuer
}

async fn oid4vp_verifier() -> impl oid4vp::Verifier {
    println!("Initializing oid4vp verifier...");
    let kms = LocalKms::new();
    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

    let verifier = oid4vp::VerifierBuilder::new(kms, key_metadata, did)
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

fn sample_issuer_metadata(iss_url: &str, authz_url: &str) -> IssuerMetadata {
    let metadata = serde_json::from_value(json!(
        {
          "credential_issuer": iss_url,
          "authorization_servers": [authz_url],
          "credential_endpoint": iss_url.to_owned()+"/credential",
          "credential_configurations_supported": {
            "SD_JWT_cred_1": {
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
              "credential_definition": {
                  "type": "SD_JWT_cred",
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
                }
            },
            "SD_JWT_cred_2": {
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
              "credential_definition": {
                  "type": "SD_JWT_cred",
                  "claims": {
                    "email": {},
                    "username": {},
                  }
                }
            }
          }
        }
    ));

    metadata.unwrap()
}

pub fn default_presentation_definition() -> PresentationDefinition {
    serde_json::from_str(TEST_PRESENTATION_DEFINITION).unwrap()
}

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
            }
        ]
    }"#;
