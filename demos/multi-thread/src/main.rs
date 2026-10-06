use actix_web::http::header::Header;
use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use equs_sdk::did::didkey::DIDKey;
use equs_sdk::did::universal::UniversalResolver;
use equs_sdk::did::{DIDBuf, DIDResolver, DID};
use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::inmem::vault::InMemVault;
use equs_sdk::kms;
use equs_sdk::kms::Kms;
use equs_sdk::reqwest::builder::ReqwestClientBuilder;
use equs_sdk::vc::core::KeyMetadata;
use equs_sdk::vc::oid4vci;
use equs_sdk::vc::oid4vci::{
    AccessToken, AuthorizationMetadata, CredentialRequest, CredentialResponseResolved,
    CredentialResult, IssuerDiscovery, IssuerMetadata,
};
use equs_sdk::vc::oid4vci::{Holder, Issuer};
use rand::distr::Alphanumeric;
use rand::{rng, Rng};
use serde_json::json;
use std::env;

const DEFAULT_RUNS: u32 = 100;

const SERVER_URL: &str = "http://localhost:4000";
// Contains scope `SD_JWT_cred`
fn dummy_token() -> String {
    let authz = &test_fixtures::keys().authz;
    test_fixtures::jws(
        &json!({ "alg": "RS256", "typ": "JWT", "kid": authz.key_id }),
        &json!({
            "exp": 1724398494,
            "iat": 1724398194,
            "auth_time": 1724398182,
            "jti": "0b4fe390-4921-4042-b7e1-b03b3d196229",
            "iss": "http://localhost:8080/idp/realms/pid-issuer-realm",
            "sub": "60b8ba5f-c73f-4976-b0da-48d0e53335de",
            "typ": "Bearer",
            "azp": "wallet-dev",
            "sid": "f15b3e11-ff28-44df-8fcf-a77d24714a23",
            "allowed-origins": ["/*"],
            "scope": "SD_JWT_cred"
        }),
        authz,
    )
}

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

    let rand_string: String = rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    let claims = json!({
        "id": rand_string,
        "given_name": "John",
        "family_name": "Doe"
    })
    .try_into()
    .unwrap();

    let resp = state
        .issuer
        .issue_credential(&cred_req, &token, &claims, None)
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
        .with_http_client(ReqwestClientBuilder::new().insecure().build().unwrap())
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
    let dummy_token = AccessToken::new(dummy_token());

    let kms = LocalKms::new();
    let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

    let holder = oid4vci_holder(
        sample_issuer_metadata(SERVER_URL),
        dummy_authorization_metadata(),
        kms,
    )
    .await;

    let res = holder
        .request_credential(&dummy_token, "SD_JWT_cred", &[key_metadata])
        .await;

    match res {
        Ok(CredentialResponseResolved {
            data: CredentialResult::Credential { .. },
            ..
        }) => Ok(()),
        Ok(_) => Err("Unexpected result".into()),
        Err(err) => Err(format!("{err:?}")),
    }
}

async fn oid4vci_holder(
    issuer_metadata: IssuerMetadata,
    authz_metadata: AuthorizationMetadata,
    kms: LocalKms,
) -> impl Holder {
    let vault = InMemVault::new();

    oid4vci::HolderBuilder::new(
        kms,
        vault,
        "wallet-dev".to_owned(),
        IssuerDiscovery::Metadata(issuer_metadata, authz_metadata),
        ReqwestClientBuilder::new().insecure().build().unwrap(),
    )
    .build()
    .await
    .unwrap()
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh).unwrap();

    let vm = UniversalResolver::default()
        .resolve_into_any_verification_method(DIDBuf::from_string(did.clone()).unwrap().as_did())
        .await
        .unwrap()
        .unwrap()
        .id;

    (
        did,
        KeyMetadata {
            kid,
            did_url: vm.to_string(),
        },
    )
}

fn sample_issuer_metadata(iss_url: &str) -> IssuerMetadata {
    let metadata = serde_json::from_value(json!(
        {
            "credential_issuer": iss_url,
            "authorization_servers": ["https://example.com"],
            "credential_endpoint": iss_url.to_owned()+"/credential",
            "credential_configurations_supported": {
                "SD_JWT_cred": {
                    "format": "dc+sd-jwt",
                    "scope": "SD_JWT_cred",
                    "vct": "https://credentials.example.com/identity_credential",
                    "credential_metadata": {
                        "claims": [
                            { "path": ["id"] },
                            { "path": ["given_name"] },
                            { "path": ["family_name"] },
                        ],
                    },
                    "credential_signing_alg_values_supported": [
                        "ES256",
                        "ES256K",
                        "EdDSA"
                    ],
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
