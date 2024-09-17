use actix_web::http::header::Header;
use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::{DIDResolver, DID};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::oid4vci;
use agent_sdk::vc::oid4vci::{
    AuthorizationMetadata, CredentialRequest, CredentialResponseResolved, CredentialResult,
    IssuanceSession, IssuerDiscovery, IssuerMetadata, Nonce, NonceData,
};
use agent_sdk::vc::oid4vci::{Holder, Issuer};
use oauth2::AccessToken;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::json;
use std::env;

const DEFAULT_RUNS: u32 = 100;

const SERVER_URL: &str = "http://localhost:4000";
// Contains scope `SD_JWT_cred`
const DUMMY_TOKEN: &str =  "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQY2xZUDZ2UmsxTHBLRGZqU08yRGEzNXJtR1JmaTkzNjJDcFJFeUpmOHAwIn0.eyJleHAiOjE3MjQzOTg0OTQsImlhdCI6MTcyNDM5ODE5NCwiYXV0aF90aW1lIjoxNzI0Mzk4MTgyLCJqdGkiOiIwYjRmZTM5MC00OTIxLTQwNDItYjdlMS1iMDNiM2QxOTYyMjkiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvaWRwL3JlYWxtcy9waWQtaXNzdWVyLXJlYWxtIiwic3ViIjoiNjBiOGJhNWYtYzczZi00OTc2LWIwZGEtNDhkMGU1MzMzNWRlIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoid2FsbGV0LWRldiIsInNpZCI6ImYxNWIzZTExLWZmMjgtNDRkZi04ZmNmLWE3N2QyNDcxNGEyMyIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJzY29wZSI6IlNEX0pXVF9jcmVkIn0.pLGGmOApXnQCY6CwuFzxFXEN36aDJ-iE0TM_esYJ_qtijhUtWq5zI9lD-iGzhTSdwZ7Y51eUKtqmJXHixzBo847vmMeGla4Ko6JTY-4vVAIQ1Hk1xzl25ALuZNwxGbljlysjzBgCxeAjZo3fE0HTI5y6NItptIU8aY3ykoIX9xE81ZkexbVrR495cEX7UIgUgCZyhj8lXUMWFrNFBhELnzzFGdX01Dq3B-KflY9ACVaw-_U9bT6EzDI0-0Cyx2K658EU9VpDjBSR6URT5I9quvx1qoYMFPv7zhjW3sUASIVwThe4CvWCCR8Kf8rsnEQ2qnchn0f6gn9thxi51FGkvA";
const DUMMY_NONCE: &str = "nOncE";

struct AppState {
    issuer: Box<dyn Issuer>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 20)]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let mode = args.get(1).expect("Specify command: `issuer`|`holders`");
    println!("MODE: {mode}");

    match mode.as_ref() {
        "issuer" => start_issuer().await,
        "holders" => {
            let runs = args.get(2).map(|runs| runs.parse::<u32>().unwrap_or(DEFAULT_RUNS)).unwrap_or(DEFAULT_RUNS);
            start_holders(runs).await;
        }
        _ => panic!("Set `issuer` to run Issuer API as cmd line arg, set `holders <num>` to run multiple holders")
    }
}

async fn start_issuer() {
    let app_state = web::Data::new(AppState {
        issuer: Box::new(oid4vci_issuer(sample_issuer_metadata(SERVER_URL)).await),
    });

    HttpServer::new(move || {
        App::new()
            .route("/credential", web::post().to(issue_endpoint))
            .app_data(app_state.clone())
    })
    .bind(("127.0.0.1", 4000))
    .unwrap()
    .run()
    .await
    .unwrap();
}

async fn issue_endpoint(
    state: web::Data<AppState>,
    req: HttpRequest,
    cred_req: web::Json<CredentialRequest>,
) -> Result<HttpResponse, Error> {
    let token = Authorization::<Bearer>::parse(&req)?
        .into_scheme()
        .token()
        .to_owned();

    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let claims = json!({
        "id": rand_string,
        "given_name": "John",
        "family_name": "Doe"
    });

    let mut dummy_session = IssuanceSession {
        nonce: Some(NonceData {
            nonce: Nonce::new(DUMMY_NONCE.into()),
            expires_in: None,
            created: None,
        }),
        notification_id: None,
        transaction_id: None,
    };

    let resp = state
        .issuer
        .issue_credential(&cred_req, &token, &claims, &mut dummy_session)
        .await;

    match resp {
        Ok(body) => Ok(HttpResponse::Ok().json(body)),
        // Protocol errors are expected
        Err(oid4vci::Error::Protocol { source }) => Ok(HttpResponse::BadRequest().json(source)),
        Err(_) => Ok(HttpResponse::InternalServerError().json(json!({}))),
    }
}

async fn oid4vci_issuer(issuer_metadata: IssuerMetadata) -> impl Issuer {
    let kms = LocalKms::new();
    let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

    oid4vci::IssuerBuilder::new(kms, issuer_metadata, key_metadata)
        .build()
        .await
        .unwrap()
}

async fn start_holders(runs: u32) {
    let mut tasks = vec![];
    for i in 0..runs {
        tasks.push(tokio::spawn(async move {
            let res = run_holder().await;

            match res {
                Ok(_) => println!("{i}: issued"),
                Err(err) => panic!("{i}: failed: {err}"),
            }
        }));
    }

    let res = futures::future::join_all(tasks).await;

    let ok = res.iter().all(|res| res.is_ok());
    let failed = res.iter().filter(|res| res.is_err()).count();
    let percentage = failed as f32 / runs as f32 * 100f32;
    if ok {
        println!("Success");
    } else {
        println!("Failed {failed} ({percentage}%) holders!");
    }
}

async fn run_holder() -> Result<(), String> {
    let dummy_token = AccessToken::new(DUMMY_TOKEN.into());

    let holder = oid4vci_holder(
        sample_issuer_metadata(SERVER_URL),
        dummy_authorization_metadata(),
    )
    .await;

    let res = holder
        .request_credential(
            &dummy_token,
            "SD_JWT_cred",
            Some(Nonce::new(DUMMY_NONCE.into())),
        )
        .await;

    match res {
        Ok(CredentialResponseResolved {
            data: CredentialResult::Credential { .. },
            ..
        }) => Ok(()),
        Ok(_) => Err("Unexpected result".into()),
        Err(err) => Err(err.to_string()),
    }
}

async fn oid4vci_holder(
    issuer_metadata: IssuerMetadata,
    authz_metadata: AuthorizationMetadata,
) -> impl Holder {
    let vault = InMemVault::new();
    let kms = LocalKms::new();
    let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

    oid4vci::HolderBuilder::new(
        kms,
        vault,
        key_metadata,
        "wallet-dev".to_owned(),
        IssuerDiscovery::Metadata(issuer_metadata, authz_metadata),
    )
    .build()
    .await
    .unwrap()
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    let didkey = DIDKey::new();

    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = didkey.generate(kh).unwrap();

    let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

    (did, KeyMetadata { kid, did_url: vm })
}

fn sample_issuer_metadata(iss_url: &str) -> IssuerMetadata {
    let metadata = serde_json::from_value(json!(
        {
          "credential_issuer": iss_url,
          "authorization_servers": ["https://example.com"],
          "credential_endpoint": iss_url.to_owned()+"/credential",
          "credential_configurations_supported": {
            "SD_JWT_cred": {
              "format": "vc+sd-jwt",
              "scope": "SD_JWT_cred",
              "vct": "https://credentials.example.com/identity_credential",
              "credential_definition": {
                  "type": "SD_JWT_cred",
                  "claims": {
                    "id": {},
                    "given_name": {},
                    "family_name": {}
                  }
                }
            }
          }
        }
    ));

    metadata.unwrap()
}

fn dummy_authorization_metadata() -> AuthorizationMetadata {
    let metadata = serde_json::from_value(json!(
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/cert",
            "grant_types_supported": [
                "authorization_code",
            ],
            "response_types_supported": [
                "code",
                "token",
            ],
            "subject_types_supported": [
                "public",
            ],
            "id_token_signing_alg_values_supported": [
                "ES256",
            ],
        }
    ));

    metadata.unwrap()
}
