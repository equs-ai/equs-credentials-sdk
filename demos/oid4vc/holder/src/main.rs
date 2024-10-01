use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::{DIDResolver, DID};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::vault::CredentialEntry;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::oid4vci::{
    CredentialOffer, CredentialResponseResolved, CredentialResult, IssuerDiscovery, TokenResponse,
};
use agent_sdk::vc::oid4vci::{Holder as HolderVci, Nonce};
use agent_sdk::vc::oid4vp::{AuthorizationResponseMetadata, ResolvedAuthRequest};
use agent_sdk::vc::oid4vp::{CredentialMapping, Holder as HolderVp};
use agent_sdk::vc::HasClaims;
use agent_sdk::vc::{oid4vci, oid4vp, Credential};
use oauth2::{AccessToken, TokenResponse as _TokenResponse};
use reqwest::Url;
use std::io;
use std::io::Write;

const CRED_DEF_ID_1: &str = "SD_JWT_cred_1";
const CRED_DEF_ID_2: &str = "SD_JWT_cred_2";

const SCOPE: &str = "SD_JWT_cred_scope";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // External components creation
    let kms = LocalKms::new();
    let vault = InMemVault::new();

    // Holders creation
    let oid4vci_holder = oid4vci_holder(kms.clone(), vault.clone()).await;

    let oid4vp_holder = oid4vp_holder(kms.clone(), vault.clone()).await;

    // Running flows
    run_issuance_flow(oid4vci_holder, kms.clone()).await;
    run_presentation_flow(oid4vp_holder).await;

    println!("Done");
}

async fn run_issuance_flow(holder: impl HolderVci, kms: LocalKms) {
    println!("Issuance started");

    println!("Holder authorizing into KeyCloak to get an access_token...");
    let token_resp = authorize_holder(&holder).await;

    // In most cases there will be no nonce attached to the `token_response`
    // Holder will automatically resolve it and re-request a new nonce
    let mut nonce = token_resp.extra_fields().clone().c_nonce;

    // In the real service these should be generated beforehand/taken from configuration/persistence
    let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

    let resp = request_credential(
        &holder,
        CRED_DEF_ID_1,
        token_resp.access_token(),
        nonce,
        key_metadata,
    )
    .await;

    // For subsequent requests to the Issuer, Holder must reuse the nonce from the previous response
    nonce = resp.nonce_data.map(|d| d.nonce);
    let (_, key_metadata) = create_did_and_key_metadata(&kms).await;

    let _ = request_credential(
        &holder,
        CRED_DEF_ID_2,
        token_resp.access_token(),
        nonce,
        key_metadata,
    )
    .await;

    println!("Issuance done");
}

async fn request_credential(
    holder: &impl HolderVci,
    cred_def_id: &str,
    token: &AccessToken,
    nonce: Option<Nonce>,
    key_metadata: KeyMetadata,
) -> CredentialResponseResolved {
    println!(
        "1. Holder requesting credential `cred_def_id={}` ...",
        cred_def_id
    );

    let cred_resp = holder
        .request_credential(token, cred_def_id, nonce, &key_metadata)
        .await
        .unwrap();

    let credential = match &cred_resp.data {
        CredentialResult::Credential { credential, .. } => credential,
        _ => unreachable!(),
    };

    println!(
        "Credential ({}):\n{}",
        cred_def_id,
        serde_json::to_string_pretty(credential).unwrap()
    );

    println!(
        "2. Holder storing received credential `cred_def_id={}`...",
        cred_def_id
    );

    let metadata = DefaultMetadataProcessor::resolve_metadata(credential, key_metadata).unwrap();
    holder
        .store_credential(credential, &metadata)
        .await
        .unwrap();

    println!("Credential saved");

    cred_resp
}

async fn run_presentation_flow(holder: impl HolderVp) {
    println!("Presentation started");

    println!("1. Holder tries to parse authorization/presentation request of Verifier");

    println!("Please enter presentation request URI from http://localhost:8098/request_uri:");
    io::stdout().flush().unwrap();

    let input = input_from_console("Failed to read presentation request uri");
    let request_uri = input
        .parse()
        .unwrap_or_else(|_| panic!("Incorrect URI: {input}"));

    let auth_request = holder
        .get_authorization_request(&request_uri)
        .await
        .unwrap();

    println!(
        "Auth request received: \n{}",
        serde_json::to_string_pretty(&auth_request).unwrap()
    );

    present_credential(holder, &auth_request).await;

    println!("Presentation done");
}

async fn present_credential(holder: impl HolderVp, auth_request: &ResolvedAuthRequest) {
    println!("Please enter the number to send presentation by:\n 1 - Auto\n 2 - Selecting from the credential list");

    let mut input = input_from_console("Failed to read presentation mode");

    match input.as_str() {
        "1" => {
            println!("2. Holder sends authorization/presentation response to Verifier");
            holder
                .present_credentials_auto(auth_request, &AuthorizationResponseMetadata {})
                .await
                .unwrap();
        }
        "2" => {
            let credentials = holder
                .find_vcs_for_presentation(auth_request)
                .await
                .unwrap();

            println!("Found credentials:");

            for (id, creds) in credentials.iter() {
                let claims = get_claims_from_cred_entries(creds);
                if claims.is_empty() {
                    println!("id = {}, credentials = {:?}", id, creds)
                } else {
                    println!("id = {}, credentials = [{}]", id, claims.join(","))
                }
            }

            println!("Please enter the selected credential by splitting \"id\" and selected \"index\" with \"=\" : for example: \"Identity-1=0,Identity-2=1,...\"`");

            input = input_from_console("Failed to read the selected credential");
            let selected = collect_selected_cred_entries(input, &credentials);

            println!("2. Holder sends authorization/presentation response to Verifier");
            holder
                .present_credentials(auth_request, &selected, &AuthorizationResponseMetadata {})
                .await
                .unwrap();
        }
        _ => {
            println!("Invalid input, please retry the flow");
        }
    }
}

fn collect_selected_cred_entries(
    input_from_console: String,
    cred_entries: &CredentialMapping,
) -> CredentialMapping {
    let mut selected = CredentialMapping::new();
    for item in input_from_console.split(',') {
        let (id, index) = item
            .split_once('=')
            .expect("Could parse selected credential");

        let cred_entry: &CredentialEntry = cred_entries
            .get(id)
            .expect("selected credential is not found")
            .get(
                index
                    .parse::<usize>()
                    .expect("could convert selected index to \"int\""),
            )
            .expect("selected credential is not found");

        selected.insert(id.to_owned(), vec![cred_entry.to_owned()]);
    }

    selected
}

fn get_claims_from_cred_entries(creds: &Vec<CredentialEntry>) -> Vec<String> {
    let mut claims = vec![];

    for cred_entry in creds {
        if let Credential::SdJwt(sd_jwt) = &cred_entry.credential {
            let claim_json = sd_jwt
                .parse_claims()
                .expect("Could not retrieve claims from sd-jwt");
            let claim = serde_json::to_string_pretty(&claim_json)
                .expect("Could not convert claim from Json to String");

            claims.push(claim)
        }
    }

    claims
}

async fn oid4vp_holder(kms: LocalKms, vault: InMemVault) -> impl oid4vp::Holder {
    println!("Initializing oid4vp holder...");

    let client_id = "wallet-dev".to_owned();

    let holder = oid4vp::HolderBuilder::new(kms, vault, client_id)
        .build()
        .await
        .unwrap();

    println!("Done");

    holder
}

async fn oid4vci_holder(kms: LocalKms, vault: InMemVault) -> impl oid4vci::Holder {
    let iss_discovery = get_issuer_discovery_mode();

    println!("Initializing oid4vci holder...");
    let client_id = "wallet-dev".to_owned();

    let holder = oid4vci::HolderBuilder::new(kms, vault, client_id, iss_discovery)
        .with_redirect_url("urn:ietf:wg:oauth:2.0:oob".to_string())
        .build()
        .await
        .unwrap();

    println!("Done");

    holder
}

fn get_issuer_discovery_mode() -> IssuerDiscovery {
    println!("Please enter the number to initialize holder form:\n 1 - Issuer URL\n 2 - Credential Offer");
    let mut input = input_from_console("Failed to read holder initialization mode");

    match input.as_str() {
        "1" => {
            println!("Please enter the Issuer URL");
            input = input_from_console("Failed to read the Issuer URL");

            IssuerDiscovery::Url(input.to_string())
        }
        "2" => {
            println!("Please enter the Credential offer Json Value");
            input = input_from_console("Failed to read the value of the Credential offer");

            IssuerDiscovery::Offer(CredentialOffer::Value {
                credential_offer: serde_json::from_str(&input)
                    .expect("Failed to parse the Credential offer"),
            })
        }

        _ => {
            println!("Invalid input, please retry");
            get_issuer_discovery_mode()
        }
    }
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

async fn authorize_holder(holder: &impl oid4vci::Holder) -> TokenResponse {
    let callback = |url: Url| {
        println!("Authorization URL. Authenticate with user \"tneal\" and password \"password\"");
        println!("{}", url);

        print!("Please enter an authorization code: ");
        io::stdout().flush().unwrap();

        input_from_console("Failed to read auth code")
    };

    holder
        .authz_code_flow_with_scope(SCOPE.to_owned(), callback)
        .await
        .unwrap()
}

fn input_from_console(err_msg: &str) -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect(err_msg);

    input.replace('\n', "")
}
