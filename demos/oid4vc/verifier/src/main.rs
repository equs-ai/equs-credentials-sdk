use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::{DIDBuf, DIDResolver, DID};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::storage::InMemStorage;
use agent_sdk::kms;
use agent_sdk::kms::{CreateOptions, KeyType, Kms};
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::storage::Storage;
use agent_sdk::vc::core::KeyMetadata;

use agent_sdk::crypto::{Key, JWK};
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::inmem::nonce::LocalNonceHandler;
use agent_sdk::vc::dcql::{DCQLCredential, NonEmptyVec, DCQL};
use agent_sdk::vc::oid4vp::{
    AuthResponseOptions, AuthorizationRequestMetadata, AuthorizationResponse,
    AuthorizationResponseObject, ClientId, ClientMetadata, CredentialVerificationMetadata,
    HashAlgorithm, PassAuthRequestObject, PresentationSession, ResolvedPresentationQuery,
    TransactionDataItem, TransactionDataResponse,
};
use agent_sdk::vc::presentation_exchange::{
    ClaimFormatMap, ClaimFormatPayload, Constraints, ConstraintsField, InputDescriptor,
    PresentationDefinition,
};
use agent_sdk::vc::{oid4vp, ClaimFormatDesignation, JsonPath};
use reqwest::Url;
use serde_json::{json, Value};
use shared::vp::{AuthRequestQuery, PresentationQueryType};
use std::collections::HashMap;
use std::env;
use std::env::VarError;
use std::fs::File;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

const SERVER_URL: &str = "http://localhost:8098";
const AUTH_REQUEST_URL_PATH: &str = "/request_uri";
const AUTH_REQUEST_OBJECT_URL_PATH: &str = "/request";
const AUTH_REQUEST_OBJECT_URL_PATH_DCQL: &str = "/request/dcql";
const AUTH_RESPONSE_URL_PATH: &str = "/present";

const TRANSACTION_DATA_DCQL_PATH_ENV_VAR: &str = "TRANSACTION_DATA_DCQL_PATH";
const TRANSACTION_DATA_PD_PATH_ENV_VAR: &str = "TRANSACTION_DATA_PD_PATH";

struct AppState {
    verifier: Arc<dyn oid4vp::Verifier>,
    auth_req_obj_storage: InMemStorage<String, Option<String>>,
    presentation_session_storage: InMemStorage<String, PresentationSession>,
    transaction_data_storage: InMemStorage<String, Vec<TransactionDataItem>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let app_state = web::Data::new(AppState {
        verifier: Arc::new(verifier().await),
        auth_req_obj_storage: InMemStorage::new(),
        presentation_session_storage: InMemStorage::new(),
        transaction_data_storage: InMemStorage::new(),
    });
    HttpServer::new(move || {
        App::new()
            .route(AUTH_REQUEST_URL_PATH, web::get().to(request_uri))
            .route(
                AUTH_REQUEST_OBJECT_URL_PATH,
                web::get().to(presentation_request_object),
            )
            .route(
                AUTH_REQUEST_OBJECT_URL_PATH_DCQL,
                web::get().to(presentation_request_object),
            )
            .route(
                AUTH_RESPONSE_URL_PATH,
                web::post().to(presentation_response),
            )
            .app_data(app_state.clone())
    })
    .bind(("localhost", 8098))?
    .run()
    .await
}

async fn request_uri(
    state: web::Data<AppState>,
    query: web::Query<AuthRequestQuery>,
) -> HttpResponse {
    let response_uri =
        Url::parse(format!("{}{}", SERVER_URL, AUTH_RESPONSE_URL_PATH).as_str()).unwrap();
    let request_uri =
        Url::parse(format!("{}{}", SERVER_URL, AUTH_REQUEST_OBJECT_URL_PATH).as_str()).unwrap();

    let auth_response_options = AuthResponseOptions {
        type_: query.response_type.clone(),
        mode: query.response_mode.clone(),
        submission_uri: Some(response_uri),
        state: None,
    };
    let pass_auth_request_object = PassAuthRequestObject::ByReference {
        uri: request_uri.clone(),
        method: None,
    };
    let transaction_data = match query.query_type {
        PresentationQueryType::DCQL => {
            get_provided_transaction_data(TRANSACTION_DATA_DCQL_PATH_ENV_VAR)
                .unwrap_or(default_transaction_data_for_dcql())
        }
        PresentationQueryType::PresentationDefinition => {
            get_provided_transaction_data(TRANSACTION_DATA_PD_PATH_ENV_VAR)
                .unwrap_or(default_transaction_data_for_pd())
        }
    };

    println!(
        "Transaction data:\n{}",
        serde_json::to_string_pretty(&transaction_data).unwrap()
    );

    state
        .transaction_data_storage
        .put("td".to_string(), transaction_data.clone())
        .await
        .unwrap();

    let request_query = match query.query_type {
        PresentationQueryType::DCQL => ResolvedPresentationQuery::DCQL(default_dcql_query()),
        PresentationQueryType::PresentationDefinition => {
            ResolvedPresentationQuery::PresentationDefinition(default_presentation_definition())
        }
    };

    let (auth_req, session) = state
        .verifier
        .create_authorization_request(
            &request_query,
            &AuthorizationRequestMetadata {
                transaction_data: Some(transaction_data),
                pass_auth_request_object,
                auth_response_options,
                expected_origins: None,
            },
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
        .put("session".to_string(), session.clone())
        .await
        .unwrap();

    println!("Chosen presentation flow is: {}", query.query_type);

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(auth_req.to_string())
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
        .content_type("application/oauth-authz-req+jwt")
        .body(auth_req_object)
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
    let wallet_auth_resp = if let Some(response) = req.get("response") {
        println!("Received Encrypted Authorization Response: {}", response);
        AuthorizationResponse::Jwe(response.to_owned())
    } else {
        AuthorizationResponse::Plain(AuthorizationResponseObject {
            vp_token: serde_json::from_str(req.get("vp_token").unwrap()).unwrap(),
            presentation_submission: req
                .get("presentation_submission")
                .map(|ps| serde_json::from_str(ps.as_str()).unwrap()),
            id_token: req.get("id_token").map(ToOwned::to_owned),
            state: req.get("state").map(ToOwned::to_owned),
            transaction_data_response: req.get("transaction_data_hashes").map(|hashes| {
                TransactionDataResponse {
                    transaction_data_hashes: serde_json::from_str(hashes).unwrap(),
                    transaction_data_hashes_alg: req
                        .get("transaction_data_hashes_alg")
                        .map(|hash_algs| serde_json::from_str(hash_algs).unwrap()),
                }
            }),
        })
    };

    let session = state
        .presentation_session_storage
        .get(&"session".to_string())
        .await
        .unwrap()
        .unwrap();

    let transaction_data = state
        .transaction_data_storage
        .get(&"td".to_string())
        .await
        .unwrap()
        .unwrap();

    // Uncommenting the lines below will cause wrong transaction data hashes error.
    // let transaction_data = if transaction_data.len() == 2 {
    //     wrong_transaction_data_for_pd()
    // } else {
    //     wrong_transaction_data_for_dcql()
    // };

    let result = state
        .verifier
        .verify_presentation(
            &wallet_auth_resp,
            &session,
            &CredentialVerificationMetadata {
                transaction_data: Some(transaction_data),
                audience: None,
            },
        )
        .await;

    match result {
        Ok(verified_claims) => {
            println!(
                "Verified claims: {}",
                serde_json::to_string_pretty(&verified_claims).unwrap()
            );
        }
        Err(oid4vp::Error::Internal {
            source: oid4vp::InternalError::VCNotValid { details },
        }) => {
            println!("{details}");
        }
        Err(err) => {
            println!("Error: {err}");
        }
    }

    HttpResponse::Ok().finish()
}

async fn verifier() -> impl oid4vp::Verifier {
    println!("Initializing verifier...");
    let kms = LocalKms::new();
    let key = kms
        .create(KeyType::P256, CreateOptions::default())
        .await
        .unwrap();
    let kh = kms.get(&key).await.unwrap();
    let jwk = kh.jwk().unwrap();
    let jwk = JWK {
        key_id: Some(key),
        public_key_use: Some("enc".to_string()),
        ..jwk
    };
    let jwk = serde_json::to_value(&jwk).unwrap();
    let Value::Object(mut jwk) = jwk else {
        panic!("The jwk is not an object");
    };
    jwk.insert("alg".to_string(), Value::String("ECDH-ES".to_string()));
    let mut metadata = default_verifier_metadata();
    let mut jwks = metadata.jwks().unwrap().unwrap();
    jwks.keys.push(jwk.clone());
    metadata.0.insert(jwks);
    println!("metadata with jwks: {:?}", metadata);
    let nonce_gen = LocalNonceHandler::default();
    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

    let verifier = oid4vp::VerifierBuilder::new(
        kms,
        nonce_gen,
        key_metadata,
        ClientId::from_did(&did).unwrap(),
    )
    .with_client_metadata(metadata)
    .with_http_client(ReqwestClientBuilder::new().insecure().build().unwrap())
    .build()
    .await
    .unwrap();

    println!("Done");
    verifier
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
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

    let age_over_18_filter = json!({
        "type": "boolean",
        "const": true
    });
    let over_18_constraint = ConstraintsField::new(JsonPath::parse("$.age_over_18").unwrap())
        .set_filter(&age_over_18_filter)
        .unwrap();

    let constraints = Constraints::new()
        .add_constraint(vct_constraint)
        .add_constraint(email_constraint)
        .add_constraint(username_constraint)
        .add_constraint(country_constraint)
        .add_constraint(over_18_constraint);

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
        .add_input_descriptor(
            serde_json::from_str(INPUT_DESCRIPTOR_FOR_JSON_LD_V1_CRED_DEF).unwrap(),
        )
        .add_input_descriptor(
            serde_json::from_str(INPUT_DESCRIPTOR_FOR_JSON_LD_V2_CRED_DEF).unwrap(),
        )
        .set_name("Example with selective disclosure".to_owned())
}

pub fn default_dcql_query() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!(
        {
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [
                {
                    "id": "1",
                    "path": ["username"],
                },
                {
                    "id": "2",
                    "path": ["email", "work"]
                },
                {
                    "id": "3",
                    "path": ["age_over_18"]
                },
                {
                    "id": "4",
                    "path": ["country"]
                },
            ],
            "multiple": true,
            "claim_sets": [["1"], ["2"], ["3"], ["4"]]
        }
    ))
    .unwrap();

    DCQL::new(NonEmptyVec::new(desc))
}

const INPUT_DESCRIPTOR_FOR_JSON_LD_V1_CRED_DEF: &str = r#"{
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

const INPUT_DESCRIPTOR_FOR_JSON_LD_V2_CRED_DEF: &str = r#"{
    "id": "alumni-card",
    "name": "University VC",
    "purpose": "We want a diploma",
    "format": {
        "ldp_vc": {
           "proof_type": [
            "EcdsaRdfc2019",
            "EdDsaRdfc2022"
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
                        "const": "AlumniCredential"
                    }
                }
            }
        ]
    }
}"#;

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
  ],
  "jwks": {
    "keys": []
  },
  "encrypted_response_enc_values_supported": [
    "A256GCM"
  ]
}"#;

pub fn default_transaction_data_for_pd() -> Vec<TransactionDataItem> {
    vec![
        TransactionDataItem {
            type_: "type1".to_string(),
            credential_ids: vec!["Identity-1".to_string()],
            transaction_data_hashes_alg: Some(vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512]),
            content: None,
        },
        TransactionDataItem {
            type_: "type2".to_string(),
            credential_ids: vec!["resident-card".to_string()],
            transaction_data_hashes_alg: None,
            content: None,
        },
        // Uncommenting the below TD will cause an error with pd flow as the credential with "non-existing" doesn't exist
        // TransactionDataItem {
        //     type_: "type2".to_string(),
        //     credential_ids: vec!["non-existing".to_string()],
        //     transaction_data_hashes_alg: Some(vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512]),
        // },
    ]
}
pub fn wrong_transaction_data_for_pd() -> Vec<TransactionDataItem> {
    vec![
        TransactionDataItem {
            type_: "type-fake".to_string(),
            credential_ids: vec!["Identity-1".to_string()],
            transaction_data_hashes_alg: Some(vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512]),
            content: None,
        },
        TransactionDataItem {
            type_: "type-fake".to_string(),
            credential_ids: vec!["resident-card".to_string()],
            transaction_data_hashes_alg: None,
            content: None,
        },
    ]
}

pub fn get_provided_transaction_data(env_var: &str) -> Option<Vec<TransactionDataItem>> {
    match env::var(env_var) {
        Ok(value) => {
            let file = File::open(value.clone())
                .unwrap_or_else(|err| panic!("Failed to open file: {}", err));
            serde_json::from_reader(file)
                .unwrap_or_else(|err| panic!("Failed to read transactional data from file {}", err))
        }
        Err(err) => match err {
            VarError::NotPresent => None,
            VarError::NotUnicode(_) => {
                eprintln!("Environment variable {} contains bad symbols.", env_var);
                None
            }
        },
    }
}

pub fn default_transaction_data_for_dcql() -> Vec<TransactionDataItem> {
    vec![
        TransactionDataItem {
            type_: "type1".to_string(),
            credential_ids: vec!["pid".to_string()],
            transaction_data_hashes_alg: Some(vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512]),
            content: None,
        },
        // Uncommenting the below TD will cause an error with dcql flow as the credential with "non-existing" doesn't exist
        // TransactionDataItem {
        //     type_: "type2".to_string(),
        //     credential_ids: vec!["non-existing".to_string()],
        //     transaction_data_hashes_alg: Some(vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512]),
        // },
    ]
}

pub fn wrong_transaction_data_for_dcql() -> Vec<TransactionDataItem> {
    vec![TransactionDataItem {
        type_: "type-fake".to_string(),
        credential_ids: vec!["pid".to_string()],
        transaction_data_hashes_alg: Some(vec![HashAlgorithm::Sha256, HashAlgorithm::Sha512]),
        content: None,
    }]
}
