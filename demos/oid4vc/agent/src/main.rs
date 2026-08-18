//! Agent (Delegate Holder) demo service for the dSD-JWT delegation flow.
//!
//! The Agent plays two OID4VP roles:
//!   * **Verifier toward the Holder** (this file, Task 5): it builds Authorization
//!     Request 2 carrying a `delegate` transaction-data item (the Agent's `cnf` +
//!     the Merchant-supplied `purchase_id`), serves it, and captures the dSD-JWT
//!     grant the Holder returns.
//!   * **Wallet toward the Merchant** (Task 6): it presents the captured grant with
//!     its own KB-JWT.
//!
//! Endpoints:
//!   * `GET /checkout`     — starts purchase flow (starts OID4VP with the Merchant).
//!   * `GET  /request_uri` — returns the Authorization Request URI (by reference).
//!   * `GET  /request`     — returns the signed Authorization Request object (JWT).
//!   * `POST /present`     — receives the Holder's delegation grant, stores it in the
//!     Agent's wallet vault, and (if a checkout is active) presents it to the Merchant.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use actix_web::mime::APPLICATION_JSON;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, ResponseError, web};
use agent_sdk::crypto::{JWK, Key};
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DID, DIDBuf, DIDResolver};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::nonce::LocalNonceHandler;
use agent_sdk::inmem::storage::InMemStorage;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::kms::{self, CreateOptions, KeyType, Kms};
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::storage::Storage;
use agent_sdk::vault::Vault;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::dcql::{DCQL, DCQLCredential, NonEmptyVec};
use agent_sdk::vc::oid4vp::{
    self, AuthResponseOptions, AuthorizationRequestMetadata, AuthorizationResponse,
    AuthorizationResponseMetadata, AuthorizationResponseObject, ClientId, ClientMetadata,
    CredentialVerificationMetadata, DelegationRequest, Holder, PassAuthRequestObject,
    PresentationResult, PresentationSession, ResolvedPresentationQuery, ResponseMode, ResponseType,
    TransactionDataItem, TransactionDataResponse, delegate_transaction_data_item,
};
use agent_sdk::vc::{Credential, CredentialMetadata, Presentation, VCFormat};
use reqwest::Url;
use serde_json::{Value, json};
use shared::voucher::{VOUCHER_DCQL_ID, VOUCHER_VCT, generate_purchase_id, purchase_id_from_dcql};
use snafu::{ResultExt, Snafu, whatever};
use std::collections::HashMap;

const SERVER_URL: &str = "http://localhost:8108";
const CHECKOUT_PATH: &str = "/checkout";
const REQUEST_URI_PATH: &str = "/request_uri";
const REQUEST_OBJECT_PATH: &str = "/request";
const PRESENT_PATH: &str = "/present";

/// Demo-wide handler error built via `snafu`'s whatever pattern: any fallible step uses
/// `.whatever_context("…")?` (or `whatever!("…")`) instead of matching/`map_err`-ing each
/// error. Rendered to the client as `500` with the full context → cause chain.
#[derive(Debug, Snafu)]
#[snafu(whatever, display("{message}"))]
struct AppError {
    message: String,
    #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        // Fold the context message and its underlying cause chain into one line.
        let mut chain = self.to_string();
        let mut cause = std::error::Error::source(self);
        while let Some(err) = cause {
            chain.push_str(&format!(": {err}"));
            cause = err.source();
        }
        println!("request failed: {chain}");
        HttpResponse::InternalServerError().body(chain)
    }
}

struct AppState {
    verifier: Arc<dyn oid4vp::Verifier>,
    /// The Agent's public confirmation key, embedded as `cnf` in the delegate payload.
    agent_jwk: JWK,
    /// The KMS holding the Agent's `cnf`/KB key — used by the wallet side to sign the
    /// trailing KB-JWT when presenting the grant to the Merchant.
    agent_kms: LocalKms,
    /// Key metadata for the Agent's `cnf`/KB key (its `kid` is the grant entry's signing key).
    agent_key_metadata: KeyMetadata,
    /// The `purchase_id` the Merchant generated for this checkout, set by `/checkout`
    /// from the Merchant's Authorization Request (defaulted until then).
    purchase_id: Mutex<String>,
    /// The Merchant's Authorization Request request URI, set by `/checkout`; used to present the grant.
    merchant_request_uri: Mutex<Option<String>>,
    /// The Agent's wallet vault. The dSD-JWT delegation grant captured by `/present` is stored
    /// here (bound to the Agent's `cnf`/KB key); the wallet side then discovers it from the vault
    /// via `present_credentials_auto` when presenting to the Merchant.
    agent_vault: InMemVault,
    auth_req_obj_storage: InMemStorage<String, Option<String>>,
    presentation_session_storage: InMemStorage<String, PresentationSession>,
    transaction_data_storage: InMemStorage<String, Vec<TransactionDataItem>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let (verifier, agent_kms, agent_jwk, agent_key_metadata) = init_agent().await;

    let app_state = web::Data::new(AppState {
        verifier: Arc::new(verifier),
        agent_jwk,
        agent_kms,
        agent_key_metadata,
        purchase_id: Mutex::new(generate_purchase_id()),
        merchant_request_uri: Mutex::new(None),
        agent_vault: InMemVault::new(),
        auth_req_obj_storage: InMemStorage::new(),
        presentation_session_storage: InMemStorage::new(),
        transaction_data_storage: InMemStorage::new(),
    });

    println!("Agent (Delegate Holder) listening on {SERVER_URL}");

    HttpServer::new(move || {
        App::new()
            .route(CHECKOUT_PATH, web::post().to(checkout))
            .route(REQUEST_URI_PATH, web::get().to(request_uri))
            .route(REQUEST_OBJECT_PATH, web::get().to(request_object))
            .route(PRESENT_PATH, web::post().to(present))
            .app_data(app_state.clone())
    })
    .bind(("localhost", 8108))?
    .run()
    .await
}

/// Build Authorization Request `delegate` and return its request URI.
async fn request_uri(state: web::Data<AppState>) -> HttpResponse {
    let auth_req = create_authorization_request(&state).await;
    HttpResponse::Ok().content_type("text/plain").body(auth_req)
}

/// Build Authorization Request (the `delegate` request), persist its session and
/// transaction data, and return the pasteable request URI string.
/// Shared by `/request_uri` and `/checkout`.
async fn create_authorization_request(state: &AppState) -> String {
    let response_uri = Url::parse(format!("{SERVER_URL}{PRESENT_PATH}").as_str()).unwrap();
    let request_uri = Url::parse(format!("{SERVER_URL}{REQUEST_OBJECT_PATH}").as_str()).unwrap();

    let auth_response_options = AuthResponseOptions {
        type_: ResponseType::VpToken,
        mode: ResponseMode::DirectPost,
        submission_uri: Some(response_uri),
        state: None,
    };
    let pass_auth_request_object = PassAuthRequestObject::ByReference {
        uri: request_uri.clone(),
        method: None,
    };

    // Build the delegate transaction-data item: the Agent asks the Holder to
    // delegate the voucher, injecting the Merchant-supplied `purchase_id` and the
    // Agent's `cnf` so the Agent can later add its own KB-JWT (dSD-JWT+KB).
    let purchase_id = state.purchase_id.lock().unwrap().clone();
    let mut payload_claims = serde_json::Map::new();
    payload_claims.insert("purchase_id".to_string(), json!(purchase_id));

    let delegation_request = DelegationRequest::holder_binding(
        vec![VOUCHER_DCQL_ID.to_string()],
        state.agent_jwk.clone(),
        payload_claims,
    )
    .unwrap();

    let nonce_handler = LocalNonceHandler::default();
    let delegate_item = delegate_transaction_data_item(&delegation_request, &nonce_handler)
        .await
        .expect("building the delegate transaction-data item");
    let transaction_data = vec![delegate_item];

    let request_query = ResolvedPresentationQuery::DCQL(voucher_dcql());

    let (auth_req, session) = state
        .verifier
        .create_authorization_request(
            &request_query,
            &AuthorizationRequestMetadata {
                transaction_data: Some(transaction_data.clone()),
                pass_auth_request_object,
                auth_response_options,
                expected_origins: None,
                client_metadata: None,
                verifier_info: None,
            },
            None,
        )
        .await
        .expect("creating authorization request");

    state
        .auth_req_obj_storage
        .put(request_uri.to_string(), session.auth_request_jwt.to_owned())
        .await
        .unwrap();
    state
        .presentation_session_storage
        .put("session".to_string(), session)
        .await
        .unwrap();
    state
        .transaction_data_storage
        .put("td".to_string(), transaction_data)
        .await
        .unwrap();

    println!("Created VC delegation request for purchase_id = {purchase_id}");

    auth_req.to_string()
}

/// Serve the signed request object (JWT).
async fn request_object(req: HttpRequest, state: web::Data<AppState>) -> HttpResponse {
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

/// Receive the Holder's delegation grant and store it.
/// If there is an active purchase, send Authorization Response to Merchant.
async fn present(
    state: web::Data<AppState>,
    req: web::Form<HashMap<String, String>>,
) -> Result<HttpResponse, AppError> {
    if let Some(error) = req.get("error") {
        println!(
            "Authorization Response error = {error}, description = {}",
            req.get("error_description")
                .map(String::as_str)
                .unwrap_or("")
        );
        return Ok(HttpResponse::Ok().finish());
    }

    let wallet_auth_resp = parse_auth_response(&req);

    let session = state
        .presentation_session_storage
        .get(&"session".to_string())
        .await
        .unwrap()
        .unwrap();

    // Verify and extract the grant. We pass `transaction_data: None`: the grant is a
    // dSD-JWT (no transaction-data hashes are returned for a delegate grant), and its
    // authenticity comes from the chain signature plus the `aud`/`nonce`/`purchase_id`
    // bound into the delegate payload.
    let (claims, presentations) = state
        .verifier
        .verify_and_extract_presentation(
            &wallet_auth_resp,
            &session,
            &CredentialVerificationMetadata {
                transaction_data: None,
                audience: None,
            },
        )
        .await
        .whatever_context("verifying/extracting the delegation grant")?;

    println!(
        "Verified claims:\n{}",
        serde_json::to_string_pretty(&claims).unwrap()
    );

    let Some(Presentation::SdJwtVp(grant)) =
        presentations.get(VOUCHER_DCQL_ID).and_then(|v| v.first())
    else {
        whatever!("no dSD-JWT grant in response for `{VOUCHER_DCQL_ID}`");
    };
    let grant = grant.clone();

    println!("Captured delegated voucher grant:\n{grant}");

    // Save the grant to the Agent's wallet vault so it can be discovered and presented via
    // `present_credentials_auto` instead of being passed around as a raw string. The entry is
    // bound to the Agent's `cnf`/KB key so the wallet signs the trailing KB-JWT with it. The
    // index `fields` cover the claim paths the Merchant's voucher DCQL queries, so vault
    // discovery surfaces the grant as a candidate.
    let metadata = CredentialMetadata {
        type_: VOUCHER_VCT.to_string(),
        format: VCFormat::SdJwtVc,
        kid: state.agent_key_metadata.kid.clone(),
        alg: None,
        fields: vec![
            "$.vct".to_string(),
            "$.purchase_id".to_string(),
            "$.amount".to_string(),
            "$.currency".to_string(),
        ],
    };
    state
        .agent_vault
        .store_credential(Credential::SdJwt(grant), &metadata)
        .await
        .whatever_context("storing the delegation grant in the vault")?;

    // Auto-trigger Auth Response to Merchant: present the stored grant to the Merchant,
    // if /checkout has supplied the Merchant's Authorization Request URI.
    let Some(uri) = state.merchant_request_uri.lock().unwrap().clone() else {
        println!("Grant stored; no Merchant request URI set (run /checkout first to present).");
        return Ok(HttpResponse::Ok().body("grant stored (no checkout in progress)"));
    };

    let outcome = present_grant_to_merchant(&state, &uri).await?;
    Ok(HttpResponse::Ok()
        .content_type(APPLICATION_JSON)
        .body(serde_json::to_string(&outcome).unwrap()))
}

/// `/checkout`: start a purchase. Fetch the Merchant's Authorization Request, extract the
/// Merchant-generated `purchase_id`, and return the Authorization Request URI for the
/// End-User to paste into the Holder CLI.
async fn checkout(
    state: web::Data<AppState>,
    req: web::Form<HashMap<String, String>>,
) -> Result<HttpResponse, AppError> {
    let Some(merchant_request_uri) = req.get("merchant_request_uri") else {
        whatever!("missing `merchant_request_uri`");
    };

    let wallet = build_wallet(&state).await?;

    let merchant_url =
        Url::parse(merchant_request_uri).whatever_context("bad merchant_request_uri")?;

    let purchase_auth_request = wallet
        .get_authorization_request(&merchant_url)
        .await
        .whatever_context("fetching Merchant Authorization Request")?;

    let purchase_id = match &purchase_auth_request.resolved_presentation_query {
        ResolvedPresentationQuery::DCQL(dcql) => purchase_id_from_dcql(dcql),
        _ => None,
    };
    let Some(purchase_id) = purchase_id else {
        whatever!("Merchant Authorization Request DCQL does not carry a purchase_id constraint");
    };

    println!("Checkout: Merchant requires purchase_id = {purchase_id}");
    *state.purchase_id.lock().unwrap() = purchase_id.clone();
    *state.merchant_request_uri.lock().unwrap() = Some(merchant_request_uri.to_owned());

    let request_uri = create_authorization_request(&state).await;

    let body = format!(
        "Checkout started for purchase_id = {purchase_id}.\n\
         Paste this request URI into the Holder CLI (cross-device present flow) to delegate the voucher:\n\n{request_uri}\n"
    );
    Ok(HttpResponse::Ok().content_type("text/plain").body(body))
}

/// Present the grant stored in the Agent's vault to the Merchant with the Agent's own KB-JWT.
async fn present_grant_to_merchant(
    state: &AppState,
    merchant_request_uri: &str,
) -> Result<Value, AppError> {
    let wallet = build_wallet(state).await?;

    let merchant_url =
        Url::parse(merchant_request_uri).whatever_context("bad merchant_request_uri")?;
    let purchase_auth_request = wallet
        .get_authorization_request(&merchant_url)
        .await
        .whatever_context("fetching Merchant Auth Request")?;

    let result = wallet
        .present_credentials_auto(
            &purchase_auth_request,
            &AuthorizationResponseMetadata::default(),
        )
        .await
        .whatever_context("presenting to Merchant")?;

    let message = match result {
        PresentationResult::Presented => {
            "Presented delegated voucher to Merchant (direct_post).".to_string()
        }
        PresentationResult::RedirectUri(url) => {
            format!("Merchant redirect URI: {url}")
        }
        PresentationResult::AuthorizationResponse(_) => {
            "Built authorization response (not posted).".to_string()
        }
    };
    println!("{message}");
    Ok(json!({"message": message}))
}

/// Build the Agent's wallet (an OID4VP Holder) over the Agent's `cnf`/KB KMS and shared vault.
async fn build_wallet(state: &AppState) -> Result<impl Holder, AppError> {
    oid4vp::HolderBuilder::new(
        state.agent_kms.clone(),
        state.agent_vault.clone(),
        "agent-wallet".to_string(),
        ReqwestClientBuilder::new()
            .insecure()
            .build()
            .whatever_context("building http client")?,
    )
    .build()
    .await
    .whatever_context("building wallet")
}

/// Authorization Request query: the voucher by `vct` only. The Holder has not yet seen `purchase_id`,
/// so it is *not* a match constraint here — it is injected via the delegate payload.
fn voucher_dcql() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!({
        "id": VOUCHER_DCQL_ID,
        "format": "dc+sd-jwt",
        "meta": { "vct_values": [VOUCHER_VCT] },
        "claims": [
            { "id": "amt", "path": ["amount"] },
            { "id": "cur", "path": ["currency"] }
        ],
    }))
    .expect("Authorization Request voucher DCQL is valid");
    DCQL::new(NonEmptyVec::new(desc))
}

fn parse_auth_response(req: &HashMap<String, String>) -> AuthorizationResponse {
    if let Some(response) = req.get("response") {
        return AuthorizationResponse::Jwe(response.to_owned());
    }
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
                    .map(|alg| serde_json::from_str(alg).unwrap()),
            }
        }),
    })
}

/// Initialize the Agent's verifier (toward the Holder) plus a separate key for the
/// delegate `cnf` / KB-JWT (used by the wallet side). Mirrors the verifier demo.
async fn init_agent() -> (impl oid4vp::Verifier, LocalKms, JWK, KeyMetadata) {
    println!("Initializing Agent verifier...");
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
        panic!("the jwk is not an object");
    };
    jwk.insert("alg".to_string(), Value::String("ECDH-ES".to_string()));
    let mut metadata = default_client_metadata();
    let mut jwks = metadata.jwks().unwrap().unwrap();
    jwks.keys.push(jwk);
    metadata.0.insert(jwks);

    let nonce_gen = LocalNonceHandler::default();
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

    // The Agent's own delegate/KB key lives in a separate KMS (used by the wallet side).
    let agent_kms = LocalKms::new();
    let (agent_did, agent_key_metadata) = create_did_and_key_metadata(&agent_kms).await;
    let agent_kh = agent_kms.get(&agent_key_metadata.kid).await.unwrap();
    let agent_jwk: JWK = agent_kh.jwk().unwrap();
    println!("Agent delegate/KB DID: {agent_did}");

    (verifier, agent_kms, agent_jwk, agent_key_metadata)
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

    (did, KeyMetadata { kid, did_url })
}

fn default_client_metadata() -> ClientMetadata {
    ClientMetadata::try_from(serde_json::from_str::<Value>(DEFAULT_CLIENT_METADATA).unwrap())
        .unwrap()
}

const DEFAULT_CLIENT_METADATA: &str = r#"{
  "vp_formats_supported": {
    "dc+sd-jwt": {
        "sd-jwt_alg_values": ["EdDSA", "ES256"],
        "kb-jwt_alg_values": ["EdDSA", "ES256"]
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
