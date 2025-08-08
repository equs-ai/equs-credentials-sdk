mod user_input;

use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::nonce::LocalNonceHandler;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::vc::HasClaims;
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::dcql::{DCQL, DCQLCredential};
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::oid4vci::{
    AuthzFlow, CredentialOfferParams, CredentialResponseResolved, CredentialResult,
    IssuerDiscovery, TokenResponse,
};
use agent_sdk::vc::oid4vci::{CredentialOfferResolver, Holder as HolderVci};
use agent_sdk::vc::oid4vp::{
    AuthResponseOptions, AuthorizationResponse, AuthorizationResponseMetadata, ClientIdScheme,
    CredentialsFindResult, CredentialsMapping, PassAuthRequestObject, ResolvedAuthRequest,
    ResolvedPresentationQuery, ResponseMode, ResponseType,
};
use agent_sdk::vc::oid4vp::{CredentialMapping, Holder as HolderVp};
use agent_sdk::vc::oid4vp::{IdTokenMetadata, Verifier};
use agent_sdk::vc::presentation_exchange::{PresentationDefinition, PresentationSubmission};
use agent_sdk::vc::{Credential, oid4vci, oid4vp};
use oauth2::{AccessToken, TokenResponse as _TokenResponse};
use reqwest::Url;
use serde_json::json;
use std::collections::HashMap;
use std::io;
use uuid::Uuid;

#[cfg(not(feature = "noninteractive"))]
use user_input::cli::*;

#[cfg(feature = "noninteractive")]
use user_input::auto::*;

use crate::user_input::{
    CredentialSelectionMode, IssuerDiscoveryMode, PresentationFlow, ResolvedPresentationQueryType,
};

const CRED_DEF_ID_1: &str = "SD_JWT_cred_1";
const JSON_LD_V1_CRED_DEF_ID: &str = "JSON_LDP_cred_2";
const JSON_LD_V2_CRED_DEF_ID: &str = "JSON_LDP_cred_3";

const SCOPE: &str = "SD_JWT_cred_scope";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
        .with_writer(io::stderr)
        .init();

    // External components creation
    let kms = LocalKms::new();
    let vault = InMemVault::new();

    // Holders creation
    let (oid4vci_holder, resolved_offer) = oid4vci_holder(kms.clone(), vault.clone()).await;

    // Running OID4VCI flow
    run_issuance_flow(oid4vci_holder, kms.clone(), resolved_offer).await;

    // Running OID4VP flow
    let holder = oid4vp_holder(kms.clone(), vault.clone()).await;
    run_presentation_flow(holder, kms.clone()).await;

    // Optionally check revocation flow
    revocation_flow(kms.clone(), vault).await;

    println!("OID4VC flows are successfully completed!");
}

async fn run_issuance_flow(
    holder: impl HolderVci,
    kms: LocalKms,
    offer: Option<CredentialOfferParams>,
) {
    println!("Authorization is started");

    let token_resp = run_authz_flow(&holder, offer).await;
    println!("Issuance started");

    // In the real service these should be generated beforehand/taken from configuration/persistence
    let key_metadata_1 = create_key_metadata(&kms).await;
    let key_metadata_2 = create_key_metadata(&kms).await;

    let _ = request_credential(
        &holder,
        CRED_DEF_ID_1,
        token_resp.access_token(),
        &[key_metadata_1, key_metadata_2],
    )
    .await;

    let key_metadata = create_key_metadata(&kms).await;

    let _ = request_credential(
        &holder,
        JSON_LD_V1_CRED_DEF_ID,
        token_resp.access_token(),
        &[key_metadata],
    )
    .await;

    let key_metadata = create_key_metadata(&kms).await;
    let _ = request_credential(
        &holder,
        JSON_LD_V2_CRED_DEF_ID,
        token_resp.access_token(),
        &[key_metadata],
    )
    .await;

    println!("Issuance done");
}

async fn run_authz_flow(
    holder: &impl HolderVci,
    offer: Option<CredentialOfferParams>,
) -> TokenResponse {
    match offer {
        Some(offer) => {
            println!("Authorization by resolving credential offer is started ...");
            get_access_token_by_resolving_offer(holder, offer).await
        }
        _ => {
            println!("Authorization Code Flow is started ...");
            authorize_holder(holder).await
        }
    }
}

async fn request_credential(
    holder: &impl HolderVci,
    cred_def_id: &str,
    token: &AccessToken,
    keys_metadata: &[KeyMetadata],
) -> CredentialResponseResolved {
    println!(
        "1. Holder requesting credential `cred_def_id={}` ...",
        cred_def_id
    );

    let cred_resp = holder
        .request_credential(token, cred_def_id, keys_metadata)
        .await
        .unwrap();

    let credentials = match &cred_resp.data {
        CredentialResult::Credential { credentials, .. } => credentials,
        _ => unreachable!(),
    };

    println!(
        "Credential ({}):\n{}",
        cred_def_id,
        serde_json::to_string_pretty(credentials).unwrap()
    );

    println!(
        "2. Holder storing received credential `cred_def_id={}`...",
        cred_def_id
    );

    for (credential, key_metadata) in credentials.iter().zip(keys_metadata.iter()) {
        let metadata =
            DefaultMetadataProcessor::resolve_metadata(credential, key_metadata.clone()).unwrap();
        holder
            .store_credential(credential, &metadata)
            .await
            .unwrap();

        println!("Credential saved");
    }

    cred_resp
}

async fn run_presentation_flow(holder: impl HolderVp, kms: LocalKms) {
    let mode = ask_presentation_flow().await;
    match mode {
        PresentationFlow::CrossDevice => cross_device_presentation_flow(holder, kms).await,
        PresentationFlow::SameDevice => same_device_presentation_flow(holder, kms).await,
    }
    println!("Presentation done");
}

async fn cross_device_presentation_flow(holder: impl HolderVp, kms: LocalKms) {
    println!("1. Holder tries to parse authorization/presentation request of Verifier");

    let request_uri = ask_presentation_flow_request_uri().await;

    let auth_request = holder
        .get_authorization_request(&request_uri)
        .await
        .unwrap();

    println!(
        "Auth request received: \n{}",
        serde_json::to_string_pretty(&auth_request).unwrap()
    );

    present_credential(holder, kms, &auth_request).await;
}

async fn same_device_presentation_flow(holder: impl HolderVp, kms: LocalKms) {
    let query_type = ask_presentation_flow_query_type().await;
    let cp = match query_type {
        ResolvedPresentationQueryType::Dcql => {
            println!("Using DCQL flow ...");
            ResolvedPresentationQuery::DCQL(default_dcql_query())
        }
        ResolvedPresentationQueryType::PresentationDefinition => {
            println!("Using PresentationDefinition flow ...");
            ResolvedPresentationQuery::PresentationDefinition(default_presentation_definition())
        }
    };
    let redirect_uri = Url::parse("http://verifier.example.com/cb").unwrap();
    let client_id = format!("{}:{}", ClientIdScheme::RedirectUri, redirect_uri.as_str());
    let verifier = verifier(client_id.as_str()).await;
    println!("1.2 Verifier generates authorization request");

    let auth_resp_config = AuthResponseOptions {
        type_: ResponseType::VpToken,
        mode: ResponseMode::DCAPI,
        submission_uri: redirect_uri.to_owned(),
        state: None,
    };
    let pass_auth_req_object = PassAuthRequestObject::ByValue;

    let (request_uri, session) = verifier
        .create_authorization_request(&cp, &auth_resp_config, &pass_auth_req_object, None)
        .await
        .unwrap();

    println!("1.3 Generated presentation request uri: \n{request_uri}");

    println!("1.4 Holder starts to handle presentation request");

    let auth_request = holder
        .get_authorization_request(&request_uri)
        .await
        .unwrap();

    println!(
        "Resolved and validated presentation request: \n{}",
        serde_json::to_string_pretty(&auth_request).unwrap()
    );

    let url = present_credential(holder, kms, &auth_request)
        .await
        .unwrap();
    println!("Holder generated presentation response and embedded it into redirect uri: \n{url}");

    println!("3.1 Verifier validates presentation response");
    let presentation_resp = retrieve_auth_resp_from_uri(url);

    let verified_claims = verifier
        .verify_presentation(&presentation_resp, &session)
        .await
        .unwrap();

    println!(
        "Verifier claims: {}",
        serde_json::to_string_pretty(&verified_claims).unwrap()
    );
}

async fn revocation_flow(kms: LocalKms, vault: InMemVault) {
    if ask_revocation_confirmation().await {
        let client = reqwest::Client::new();
        println!("Sending http 'GET' request to the issuer to revoke SD-JWT credential");
        let resp = client
            .get("http://localhost:8088/revoke")
            .send()
            .await
            .unwrap();
        if resp.status().is_success() {
            println!("SD-JWT credential was revoked!");
            if ask_restart_after_revocation().await {
                println!("Restarting OID4VP flow..");

                let holder = oid4vp_holder(kms.clone(), vault.clone()).await;
                run_presentation_flow(holder, kms.clone()).await;
            }
        } else {
            println!(
                "Revoke http call is failed: status_code = {}",
                resp.status().as_u16()
            );
        }
    } else {
        println!("Revocation flow check was skipped!");
    }
}

fn retrieve_auth_resp_from_uri(url: Url) -> AuthorizationResponse {
    let presentation_resp_map: HashMap<String, String> =
        serde_urlencoded::from_str(url.fragment().unwrap()).unwrap();

    let vp_token_str = presentation_resp_map.get("vp_token").unwrap();
    let vp_token =
        serde_json::from_str(vp_token_str).unwrap_or(serde_json::to_value(vp_token_str).unwrap());

    let state = presentation_resp_map
        .get("state")
        .map(|state| state.to_owned());

    let presentation_submission: Option<PresentationSubmission> =
        match presentation_resp_map.get("presentation_submission") {
            None => None,
            Some(s) => serde_json::from_str(s).ok(),
        };

    AuthorizationResponse {
        vp_token,
        presentation_submission,
        id_token: None,
        state,
    }
}

async fn verifier(client_id: &str) -> impl Verifier {
    println!("1.1 Initializing verifier...");
    let kms = LocalKms::new();
    let nonce_gen = LocalNonceHandler::default();
    let key_metadata = create_key_metadata(&kms).await;

    let verifier =
        oid4vp::VerifierBuilder::new(kms, nonce_gen, key_metadata, client_id.to_string())
            .with_http_client(ReqwestClientBuilder::new().insecure().build().unwrap())
            .build()
            .await
            .unwrap();

    println!("Done");
    verifier
}

async fn present_credential(
    holder: impl HolderVp,
    kms: LocalKms,
    auth_request: &ResolvedAuthRequest,
) -> Option<Url> {
    let mode = ask_presentation_credential_selection_mode().await;

    let presentation_result = match mode {
        CredentialSelectionMode::Auto => {
            println!("2. Holder sends authorization/presentation response to Verifier!");

            let auth_response_metadata = resolve_auth_resp_metadata(auth_request, kms).await;
            holder
                .present_credentials_auto(auth_request, &auth_response_metadata)
                .await
        }
        CredentialSelectionMode::ManualSelection => {
            let credentials = holder
                .find_vcs_for_presentation(auth_request)
                .await
                .unwrap();

            println!("Found credentials:");

            for (id, creds) in credentials.iter() {
                let claims = get_claims_from_cred_entries(creds);
                if claims.is_empty() {
                    println!(
                        "id = {}, credentials = {}",
                        id,
                        serde_json::to_string_pretty(&creds).unwrap()
                    );
                } else {
                    println!("id = {}, credentials = [{}]", id, claims.join(","))
                }
            }

            let input = ask_credential_selection().await;
            let selected = collect_selected_cred_entries(input, &credentials);

            let auth_response_metadata = resolve_auth_resp_metadata(auth_request, kms).await;

            println!("2. Holder sends authorization/presentation response to Verifier");
            holder
                .present_credentials(auth_request, &selected, &auth_response_metadata)
                .await
        }
    };

    let redirect_url = match presentation_result {
        Ok(redirect_url) => redirect_url,
        Err(oid4vp::Error::Protocol { source }) => source.redirect_uri().cloned(),
        Err(e) => {
            panic!("Internal error while presenting credentials, {e}");
        }
    };

    if let Some(url) = redirect_url.clone() {
        println!("Redirect url: {}", url);
    }

    redirect_url
}

async fn resolve_auth_resp_metadata(
    auth_request: &ResolvedAuthRequest,
    kms: LocalKms,
) -> AuthorizationResponseMetadata {
    let mut auth_resp_metadata = if ask_presentation_claims_exclusion_confirmation().await {
        let map = ask_presentation_claims_to_exclude().await;
        AuthorizationResponseMetadata::with_excluded_claims(map)
    } else {
        Default::default()
    };

    if auth_request.response_type == ResponseType::VpTokenIdToken {
        let key_metadata = create_key_metadata(&kms).await;

        auth_resp_metadata.id_token_metadata = Some(IdTokenMetadata {
            key_metadata,
            lifetime: time::Duration::minutes(5),
        });
    }

    auth_resp_metadata
}

fn collect_selected_cred_entries(
    input_from_console: String,
    cred_entries: &CredentialsMapping,
) -> CredentialMapping {
    let mut selected = CredentialMapping::new();
    for item in input_from_console.split(',') {
        let (id, index) = item
            .split_once('=')
            .expect("Could parse selected credential");

        let cred_find_result = cred_entries
            .get(id)
            .expect("selected credential is not found");

        match cred_find_result {
            CredentialsFindResult::Credentials(creds) => {
                let cred_entry = creds
                    .get(
                        index
                            .parse::<usize>()
                            .expect("could convert selected index to \"int\""),
                    )
                    .expect("selected credential is not found");

                selected.insert(id.to_owned(), cred_entry.to_owned());
            }
            CredentialsFindResult::Reasons(reasons) => {
                panic!("Unexpected cred type reasons: {reasons:?}");
            }
        }
    }

    selected
}

fn get_claims_from_cred_entries(creds: &CredentialsFindResult) -> Vec<String> {
    match creds {
        CredentialsFindResult::Credentials(creds) => {
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
        CredentialsFindResult::Reasons(reasons) => {
            panic!("Expected credentials, found reasons: {:#?}", reasons)
        }
    }
}

async fn oid4vp_holder(kms: LocalKms, vault: InMemVault) -> impl oid4vp::Holder {
    println!("Initializing oid4vp holder...");

    let client_id = "wallet-dev".to_owned();

    let holder = oid4vp::HolderBuilder::new(
        kms,
        vault,
        client_id,
        ReqwestClientBuilder::new().insecure().build().unwrap(),
    )
    .build()
    .await
    .unwrap();

    println!("Done");

    holder
}

async fn oid4vci_holder(
    kms: LocalKms,
    vault: InMemVault,
) -> (impl oid4vci::Holder, Option<CredentialOfferParams>) {
    let (iss_discovery, resolved_offer) = get_issuer_discovery_mode().await;

    println!("Initializing oid4vci holder...");
    let client_id = "wallet-dev".to_owned();

    let holder = oid4vci::HolderBuilder::new(
        kms,
        vault,
        client_id,
        iss_discovery,
        ReqwestClientBuilder::new().insecure().build().unwrap(),
    )
    .with_redirect_url("urn:ietf:wg:oauth:2.0:oob".to_string())
    .build()
    .await
    .unwrap();

    println!("Done");

    (holder, resolved_offer)
}

async fn get_issuer_discovery_mode() -> (IssuerDiscovery, Option<CredentialOfferParams>) {
    let issuer_discovery_mode = ask_issuer_discovery_mode().await;
    match issuer_discovery_mode {
        IssuerDiscoveryMode::Url => {
            let url = ask_issuer_url().await;
            (IssuerDiscovery::Url(url), None)
        }
        IssuerDiscoveryMode::CredentialOffer => {
            let offer_params = resolve_offer().await;
            (
                IssuerDiscovery::Url(offer_params.credential_issuer.to_string()),
                Some(offer_params),
            )
        }
    }
}

async fn resolve_offer() -> CredentialOfferParams {
    let offer_url = ask_offer().await;

    CredentialOfferResolver::with_http_client(
        ReqwestClientBuilder::new().insecure().build().unwrap(),
    )
    .resolve(Url::parse(&offer_url).unwrap())
    .await
    .unwrap()
}

async fn create_key_metadata(kms: &LocalKms) -> KeyMetadata {
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
        .id
        .as_did_url()
        .to_string();

    println!("Generated DID {did}");
    println!("Generated DIDURL {vm}");

    KeyMetadata { kid, did_url: vm }
}

async fn authorize_holder(holder: &impl oid4vci::Holder) -> TokenResponse {
    let callback = |url: Url| ask_auth_code_by_url(url);

    holder
        .authz_code_flow_with_scope(SCOPE.to_owned(), callback)
        .await
        .unwrap()
}

async fn get_access_token_by_resolving_offer(
    holder: &impl oid4vci::Holder,
    offer_params: CredentialOfferParams,
) -> TokenResponse {
    let callback = async |authz_flow: AuthzFlow| {
        let code = ask_auth_code_by_flow(authz_flow).await;
        Ok::<String, io::Error>(code)
    };

    let access_token = holder
        .get_access_token(&offer_params, callback)
        .await
        .unwrap();

    print!("Access token is successfully retrieved by resolving the credential offer");

    access_token
}

pub fn default_presentation_definition() -> PresentationDefinition {
    let input_descriptor_1 = serde_json::from_str(INPUT_DESCRIPTOR_FOR_CRED_DEF_1).unwrap();
    PresentationDefinition::new(Uuid::new_v4().to_string(), input_descriptor_1)
        .add_input_descriptor(serde_json::from_str(INPUT_DESCRIPTOR_FOR_CRED_DEF_2).unwrap())
        .set_name("Example with selective disclosure".to_owned())
}

pub fn default_dcql_query() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!(
        {
            "id": "pid",
            "format": "dc+sd-jwt",
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
            "claim_sets": [["1"], ["2"], ["3"], ["4"]]
        }
    ))
    .unwrap();

    DCQL::new(vec![desc])
}

const INPUT_DESCRIPTOR_FOR_CRED_DEF_1: &str = r#"{
    "id": "Identity-1",
    "name": "Identity VC",
    "purpose": "We want a resident card",
    "format": {
        "dc+sd-jwt": {
        "sd-jwt_alg_values": [
          "ES256",
          "EdDSA"
        ],
        "kb-jwt_alg_values": [
          "ES256",
          "EdDSA"
        ]
      }
    },
    "constraints": {
        "fields": [
          {
            "path": ["$.vct"],
             "filter": {
               "type": "string",
               "const": "https://credentials.example.com/identity_credential_1"
             }
          },
          {
            "path": ["$.username"]
          },
          {
              "path": [
                "$.birthdate"
              ],
              "filter": {
                "pattern": "^(?P<year>\\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])$"
              },
              "optional": false
            },
          {
            "path": ["$.email.work"],
            "optional": false
          }
        ]
    }
}"#;

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
