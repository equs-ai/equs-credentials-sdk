use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::{DIDResolver, DID};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::kms::Kms;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::metadata::CredentialMetadataProcessor;
use agent_sdk::vc::oid4vci::Holder as HolderVci;
use agent_sdk::vc::oid4vci::{CredentialResult, TokenResponse};
use agent_sdk::vc::oid4vp::AuthorizationResponseMetadata;
use agent_sdk::vc::oid4vp::Holder as HolderVp;
use agent_sdk::vc::{oid4vci, oid4vp};
use agent_sdk::{kms, vc};
use reqwest::Url;
use std::io;
use std::io::Write;

const SERVER_URL: &str = "http://localhost:8088";
const CRED_DEF_ID: &str = "SD_JWT_cred";
const SCOPE: &str = "SD_JWT_cred";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // External components creation
    let kms = LocalKms::new();
    let vault = InMemVault::new();

    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (did, key_metadata) = create_did_and_key_metadata(&kms).await;

    // Holders creation
    let oid4vci_holder = oid4vci_holder(
        kms.clone(), vault.clone(), key_metadata.clone(), SERVER_URL,
    ).await;

    let oid4vp_holder = oid4vp_holder(
        kms.clone(), vault.clone(), did, key_metadata,
    ).await;

    // Running flows
    run_issuance_flow(oid4vci_holder).await;
    run_presentation_flow(oid4vp_holder).await;

    println!("Done");
}

async fn run_issuance_flow(holder: impl HolderVci) {
    println!("Issuance started");

    println!("1. Holder authorizing into KeyCloak to get an access_token...");
    let token_resp = authorize_holder(&holder).await;

    println!("2. Holder requesting credential...");
    let cred_resp = holder
        .request_credential(&token_resp, CRED_DEF_ID)
        .await
        .unwrap();

    let credential = match cred_resp {
        CredentialResult::Credential { credential, .. } => credential,
        _ => unreachable!()
    };

    println!("Credential:\n{}", serde_json::to_string_pretty(&credential).unwrap());

    println!("3. Holder storing received credential...");
    let metadata = vc::metadata::DefaultMetadataProcessor::resolve_metadata(&credential).unwrap();
    let _ = holder.store_credential(&credential, &metadata).await.unwrap();

    println!("Issuance done");
}

async fn run_presentation_flow(holder: impl HolderVp) {
    println!("Presentation started");

    println!("1. Holder tries to parse authorization/presentation request of Verifier");

    println!("Please enter presentation request URI from http://localhost:8088/request_uri:");
    io::stdout().flush().unwrap();

    let mut request_uri = String::new();
    io::stdin()
        .read_line(&mut request_uri)
        .expect("Failed to read presentation request uri");

    let auth_request = holder.get_authorization_request(&request_uri).await.unwrap();

    println!("Auth request received: \n{:?}", auth_request);

    println!("2. Holder sends authorization/presentation response to Verifier");
    holder.present_credentials_auto(&auth_request, &AuthorizationResponseMetadata {}).await.unwrap();

    println!("Presentation done");
}

async fn oid4vp_holder(kms: LocalKms, vault: InMemVault, did: String, key_metadata: KeyMetadata) -> impl oid4vp::Holder {
    println!("Initializing oid4vp holder...");

    let holder = oid4vp::HolderBuilder::new(kms, vault, key_metadata, did)
        .build().await.unwrap();

    println!("Done");

    holder
}

async fn oid4vci_holder(kms: LocalKms, vault: InMemVault, key_metadata: KeyMetadata, issuer_url: &str) -> impl oid4vci::Holder {
    println!("Initializing oid4vci holder...");

    let client_id = "wallet-dev".to_owned();

    let holder = oid4vci::HolderBuilder::new(kms, vault, key_metadata, client_id)
        .with_issuer_url(issuer_url.to_string())
        .with_redirect_url("urn:ietf:wg:oauth:2.0:oob".to_string())
        .build().await.unwrap();

    println!("Done");

    holder
}

async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    let didkey = DIDKey::new();

    let (kid, kh) = kms.create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await.unwrap();

    let did = didkey.generate(kh).unwrap();

    let vm = didkey.resolve_verification_method(&did)
        .await.unwrap().id;

    println!("Generated DID {}", did.clone());
    println!("Generated DIDURL {}", vm.clone());

    (did, KeyMetadata { kid, did_url: vm })
}

async fn authorize_holder(holder: &impl oid4vci::Holder) -> TokenResponse {
    let callback = |url: Url| {
        println!("Authorization URL. Authenticate with user \"tneal\" and password \"password\"");
        println!("{}", url.to_string());

        print!("Please enter an authorization code: ");
        io::stdout().flush().unwrap();

        let mut auth_code = String::new();
        io::stdin()
            .read_line(&mut auth_code)
            .expect("Failed to read auth code");

        auth_code
    };
    let token_response = holder
        .authz_code_flow_with_scope(SCOPE.to_owned(), callback)
        .await
        .unwrap();

    token_response
}
