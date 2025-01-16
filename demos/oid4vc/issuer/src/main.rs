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
    AuthorizationCodeGrant, AuthorizationMetadata, CredDefMetadata, CredDefMetadataProfile,
    CredentialOfferGrants, CredentialRequest, IssuanceSession, IssuerMetadata, IssuerUrl,
    PreAuthorizedCode, PreAuthorizedCodeGrant, TokenRequest, TokenResponse,
};
use std::collections::HashMap;
use std::ops::Add;

use actix_web::cookie::time;
use actix_web::cookie::time::OffsetDateTime;
use agent_sdk::did::didweb::DIDWeb;
use agent_sdk::did::DIDDoc;
use agent_sdk::inmem::nonce::LocalNonceGenerator;
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::vc::claims::Claims;
use agent_sdk::vc::oid4vci;
use keycloak::{KeycloakAdmin, KeycloakAdminToken};
use reqwest::Url;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const ISSUER_SERVER_URL: &str = "http://localhost:8088";
const AUTH_SRV_URL: &str = "http://localhost:8080/idp/realms/pid-issuer-realm";
const CRED_OFFER_SCHEME: &str = "openid-credential-offer://";

const CREDENTIAL_URL_PATH: &str = "/credential";
const METADATA_URL_PATH: &str = "/.well-known/openid-credential-issuer";
const CREDENTIAL_OFFER_WITH_AUTH_CODE_GRANT_URL_PATH: &str = "/credential_offer_auth_code_grant";
const CREDENTIAL_OFFER_WITH_PRE_AUTH_CODE_GRANT_URL_PATH: &str =
    "/credential_offer_pre_auth_code_grant";
const CREATE_CREDENTIAL_OFFER_URI_WITH_AUTH_CODE_GRANT_PATH: &str =
    "/create_credential_offer_uri_auth_code_grant";
const CREATE_CREDENTIAL_OFFER_URI_WITH_PRE_AUTH_CODE_GRANT_PATH: &str =
    "/create_credential_offer_uri_pre_auth_code_grant";
const DID_DOC_URL_PATH: &str = "/.well-known/did.json";
const AUTH_METADATA_ENDPOINT_PATH: &str = "/.well-known/openid-configuration";
const TOKEN_ENDPOINT_PATH: &str = "/token";
const TOKEN_INTROSPECT_PATH: &str = "/introspection";
const DUMMY_ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MzY5NDI0MTQsImlhdCI6MTczNjk0MjExNCwiYXV0aF90aW1lIjoxNzM2OTQyMTEyLCJqdGkiOiI0MzEwNjlkMS01ZjIzLTQ5MjAtYjA1Zi01NWI2NjM1MDQxODYiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6IjQwZTYyNDY3LTUzZmMtNGQyOS05ZGZmLTJlN2Y4NDRjM2UzMiIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkX3Njb3BlIn0.g4Ll7wiGq9VrxwAcGeARHB1mziDYMQBSmKHl_KGyBZccUvMGlH7ZPIegW_FLFJg4ZSz3IyId2xchuXP8LaSAghgLf9HmKA4XWlVhvx4wP90aj9bj2fdD9UUuSwQIeRlkZe7DTNookyClsqKJ2uIBzvaLoID2_4_RAvqmNi_grIe-ruus4thyp5NsQdEoudErok5DQiM_N2Wz5zg2MRrECjZL4kX-CrEiSaGaikTR-Lxc9UpvLr8mmmEwz7O4BOCDukyslzCZylmC32lttMYzU2Cno_XsIOvXtfGzwNjzZ-ohF9ThnpHvl7EexoZeDaPP2oYSDJOdrh33BB879DGuHw";

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
            .route(
                CREATE_CREDENTIAL_OFFER_URI_WITH_AUTH_CODE_GRANT_PATH,
                web::get().to(create_credential_offer_uri_with_auth_code_grant),
            )
            .route(
                CREATE_CREDENTIAL_OFFER_URI_WITH_PRE_AUTH_CODE_GRANT_PATH,
                web::get().to(create_credential_offer_uri_with_pre_auth_code_grant),
            )
            .route(
                CREDENTIAL_OFFER_WITH_AUTH_CODE_GRANT_URL_PATH,
                web::get().to(credential_offer_with_auth_code_grant),
            )
            .route(
                CREDENTIAL_OFFER_WITH_PRE_AUTH_CODE_GRANT_URL_PATH,
                web::get().to(credential_offer_with_pre_auth_code_grant),
            )
            .route(DID_DOC_URL_PATH, web::get().to(did_doc))
            .route(TOKEN_ENDPOINT_PATH, web::post().to(generate_token))
            .route(TOKEN_INTROSPECT_PATH, web::post().to(validate_token))
            .route(
                AUTH_METADATA_ENDPOINT_PATH,
                web::get().to(issuer_auth_metadata),
            )
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

    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .json(serde_json::to_value(metadata).unwrap())
}

async fn credential_offer_with_auth_code_grant(state: web::Data<AppState>) -> HttpResponse {
    let pre_auth_grant = AuthorizationCodeGrant::new(None, None)
        .set_authorization_server(Some(IssuerUrl::new(ISSUER_SERVER_URL.to_string()).unwrap()));

    let (credential_offer, url) = state
        .issuer
        .create_credential_offer(
            vec!["SD_JWT_cred_1", "JSON_LDP_cred_2"],
            &CredentialOfferGrants {
                authorization_code: Some(pre_auth_grant),
                pre_authorized_code: None,
            },
        )
        .unwrap();

    println!("Offer {:?}", credential_offer);
    println!("URL {}", url);

    HttpResponse::Ok().json(credential_offer)
}

async fn credential_offer_with_pre_auth_code_grant(state: web::Data<AppState>) -> HttpResponse {
    let pre_auth_grant = PreAuthorizedCodeGrant::new(PreAuthorizedCode::new("code".to_string()))
        .set_authorization_server(Some(IssuerUrl::new(ISSUER_SERVER_URL.to_string()).unwrap()));

    let (credential_offer, url) = state
        .issuer
        .create_credential_offer(
            vec!["SD_JWT_cred_1", "JSON_LDP_cred_2"],
            &CredentialOfferGrants {
                authorization_code: None,
                pre_authorized_code: Some(pre_auth_grant),
            },
        )
        .unwrap();

    println!("Offer {:?}", credential_offer);
    println!("URL {}", url);

    HttpResponse::Ok().json(credential_offer)
}

async fn create_credential_offer_uri_with_auth_code_grant() -> HttpResponse {
    let mut offer_uri = Url::parse(CRED_OFFER_SCHEME).unwrap();
    offer_uri.set_query(Some(&format!(
        "credential_offer_uri={ISSUER_SERVER_URL}{CREDENTIAL_OFFER_WITH_AUTH_CODE_GRANT_URL_PATH}"
    )));

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(offer_uri.to_string())
}

async fn create_credential_offer_uri_with_pre_auth_code_grant() -> HttpResponse {
    let mut offer_uri = Url::parse(CRED_OFFER_SCHEME).unwrap();
    offer_uri.set_query(Some(&format!(
        "credential_offer_uri={ISSUER_SERVER_URL}{CREDENTIAL_OFFER_WITH_PRE_AUTH_CODE_GRANT_URL_PATH}"
    )));

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(offer_uri.to_string())
}

async fn generate_token(req: web::Form<TokenRequest>) -> Result<HttpResponse, Error> {
    println!("Token request: {:?}", req.0);
    let resp: TokenResponse = serde_json::from_value(json!({
        "access_token": DUMMY_ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": 86400,
    }))?;

    Ok(HttpResponse::Ok().json(resp))
}

async fn validate_token(req: web::Form<HashMap<String, String>>) -> Result<HttpResponse, Error> {
    println!("Validate token request: {:?}", req.0.get("token").unwrap());
    let iat = OffsetDateTime::now_utc().unix_timestamp();
    let exp = OffsetDateTime::now_utc()
        .add(Duration::from_secs(300))
        .unix_timestamp();
    let resp = json!({
        "exp":iat,
        "iat":exp,
        "iss":AUTH_SRV_URL,
        "typ":"Bearer",
        "azp":"wallet-dev",
        "allowed-origins":["/*"],
        "scope":"SD_JWT_cred_scope",
        "client_id":"wallet-dev",
        "username":"tneal",
        "token_type":"Bearer",
        "active":true
    });

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .json(resp))
}

async fn issuer_auth_metadata() -> HttpResponse {
    let metadata = sample_authorization_metadata();

    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .json(serde_json::to_value(metadata).unwrap())
}

async fn did_doc(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok().json(state.did_doc.clone())
}

async fn get_user_attributes(cred_def: &CredDefMetadata) -> Result<Claims, Error> {
    let vc_type = match cred_def.profile_specific_fields() {
        CredDefMetadataProfile::VcSdJwt(m) => m.vct(),
        CredDefMetadataProfile::LdpVc(m) => &m.credential_definition().r#type()[1],
        _ => panic!("unsupported format"),
    };

    if vc_type == "PermanentResidentCard" {
        return Ok(json!({
            "type": ["PermanentResident", "Person"],
            "givenName": "John",
            "familyName": "Doe",
            "birthDate": "09/09/1989",
        })
        .try_into()
        .unwrap());
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
        claims_json["email"] = json!({
            "personal": user.email.to_owned(),
            "work": user.email.to_owned()
        });
        claims_json["postal_code"] = json!({
            "codes": [ claims_json["postal_code"][0], "10001" ]
        });
        claims_json["country"] = serde_json::Value::from("US");

        let _ = claims_json.as_object_mut().is_some_and(|m| {
            m.insert(
                "exp".to_string(),
                serde_json::Value::from(
                    OffsetDateTime::now_utc()
                        .add(time::Duration::days(365))
                        .unix_timestamp(),
                ),
            );
            m.insert(
                "nbf".to_string(),
                serde_json::Value::from(
                    OffsetDateTime::now_utc()
                        .add(time::Duration::days(1))
                        .unix_timestamp(),
                ),
            );
            m.insert(
                "iat".to_string(),
                serde_json::Value::from(OffsetDateTime::now_utc().unix_timestamp()),
            );
            true
        });

        return Ok(claims_json.try_into().unwrap());
    }

    Ok(Claims::new())
}

async fn issuer() -> (impl oid4vci::Issuer, DIDDoc) {
    println!("Initializing issuer...");
    let kms = LocalKms::new();
    let nonce_gen = LocalNonceGenerator::default();
    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (_, key_metadata, did_doc) = create_did_and_key_metadata(&kms).await;

    let issuer_metadata = sample_issuer_metadata(ISSUER_SERVER_URL, AUTH_SRV_URL);

    let issuer = oid4vci::IssuerBuilder::new(kms, nonce_gen, issuer_metadata, key_metadata)
        .with_http_client(ReqwestClientBuilder::new().insecure().build().unwrap())
        .with_clock_skew(time::Duration::minutes(1))
        .token_validation_introspect(
            // Url::parse("http://localhost:8080/idp/realms/pid-issuer-realm/protocol/openid-connect/token/introspect").unwrap(),
            Url::parse(&format!("{ISSUER_SERVER_URL}{TOKEN_INTROSPECT_PATH}")).unwrap(),
            Some(format!(
                "Basic {}",
                "cGlkLWlzc3Vlci1zcnY6eklLQVY5RElJSWFKQ3pIQ1ZCUGx5U2dVOEtnWTY4VTI="
            )),
        )
        .build()
        .await
        .unwrap();

    println!("Done");
    (issuer, did_doc)
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata, DIDDoc) {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = DIDWeb::generate_did_from_url(ISSUER_SERVER_URL).unwrap();
    let did_doc = DIDWeb::generate_did_document(&did, &kh).unwrap();
    let vm = format!("{did}#key-0");

    println!("Generated DID {}", did.clone());
    println!("Generated DIDURL {}", vm.clone());

    (did, KeyMetadata { kid, did_url: vm }, did_doc)
}

const CRED_DEF_1: &str = "SD_JWT_cred_1";
const CRED_DEF_2: &str = "JSON_LDP_cred_2";

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
                "ES256",
                "ES256K",
                "EdDSA"
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
                "email": {
                            "personal": {},
                            "work": {}
                        },
                "username": {},
                "postal_code": {"codes": [{}, {}]},
                "locality": {},
                "region": {},
                "birthdate": {},
                "gender": {},
                "country": {},
                "family_name": {},
                "country": {},
              }
            },
            CRED_DEF_2: {
                "format": "ldp_vc",
                "scope": "SD_JWT_cred_scope",
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://w3id.org/citizenship/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "PermanentResidentCard"
                ],
                "cryptographic_binding_methods_supported": [
                    "jwk"
                ],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018",
                    "EcdsaSecp256k1Signature2019"
                ],
                "credential_definition": {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://w3id.org/citizenship/v1"
                    ],
                    "type": [
                        "VerifiableCredential",
                        "PermanentResidentCard"
                    ],
                    "credentialSubject": {
                        "givenName": {},
                        "familyName": {},
                        "gender": {},
                        "birthDate": {},
                        "birthCountry": {},
                        "commuterClassification": {},
                        "residentSince": {},
                        "gpa": {}
                    }
                },
                "display": [
                    {
                        "name": "University Credential",
                        "locale": "en-US",
                        "logo": {
                            "uri": "https://exampleuniversity.com/public/logo.png",
                            "alt_text": "a square logo of a university"
                        },
                        "background_color": "#12107c",
                        "background_image": {
                            "uri": "https://university.example.edu/public/background-image.png"
                        },
                        "text_color": "#FFFFFF"
                    }
                ]
            }
          }
        }
    ));

    metadata.unwrap()
}

pub fn sample_authorization_metadata() -> AuthorizationMetadata {
    let metadata = serde_json::from_value(json!(
        {
            "issuer": ISSUER_SERVER_URL,
            "token_endpoint": ISSUER_SERVER_URL.to_owned()+TOKEN_ENDPOINT_PATH,
            "introspection_endpoint": ISSUER_SERVER_URL.to_owned()+TOKEN_INTROSPECT_PATH,
            "pre-authorized_grant_anonymous_access_supported": true,
            "grant_types_supported": [
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            ],
            "response_types_supported": [
                "token",
            ]
        }
    ));

    metadata.unwrap()
}
