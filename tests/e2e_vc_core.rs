#![allow(dead_code)]

mod utils;

use agent_sdk::crypto::Alg;
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver};
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::nonce::LocalNonceHandler;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::kms::Kms;
use agent_sdk::nonce::NonceHandler;
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::vc::VCStatusesData;
use agent_sdk::vc::core::IssuerService;
use agent_sdk::vc::core::VerifierService;
use agent_sdk::vc::core::status_issuer::StatusIssuerService;
use agent_sdk::vc::core::{
    CredentialDefinition, CredentialDefinitionData, Holder, HolderMetadata, Issuer, IssuerMetadata,
    PopFormat, StatusIssuer, StatusIssuerMetadata, StatusListDefinition, Verifier,
};
use agent_sdk::vc::core::{HolderService, KeyMetadata};
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::presentation_exchange::InputDescriptor;
use agent_sdk::vc::presentation_exchange::StatusSize;
use agent_sdk::vc::status_formats::StatusListFormat;
use agent_sdk::vc::status_formats::status_list_token_jwt::{VCStatus, VCStatuses};
use agent_sdk::{kms, vc};
use oid4vci::proof_of_possession::ProofOfPossession;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use time::Duration;
use url::Url;
use utils::fixtures::{SCOPE, VC_TYPE, VERIFIER_ID, sample_claims_sdjwt};
use utils::helpers::create_did_keymetadata_keyhandle;

const STATUS_LIST_PATH: &str = "/status_list";
const CLAIM_EXP_DAYS: i64 = 1024;
const POP_EXP_MINUTES: i64 = 8;

#[tokio::test]
async fn sd_jwt_credential_issuance_and_presentation_verification() {
    // Initialization
    let holder_kms = LocalKms::new();
    let nonce_gen = LocalNonceHandler::default();

    let issuer = build_issuer_with_sd_jwt_credential_profile().await;
    let holder = build_holder(holder_kms.clone()).await;
    let verifier = build_verifier(VERIFIER_ID);

    println!("Issue credential...");

    let offer = issuer.offer_credential(SCOPE, None);
    let offer = offer.unwrap();

    let nonce = Some(nonce_gen.generate().await.unwrap());
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&holder_kms).await;
    let request = holder
        .request_credential(&offer, nonce.clone(), &key_metadata)
        .await;
    let request = request.unwrap();

    // tests pop exp time. The exp time for pop is set during holder build
    let proof = &request.proof.proof;
    let pop = ProofOfPossession::from_jwt(proof.as_str(), UniversalResolver::default())
        .await
        .unwrap();
    let exp = time::OffsetDateTime::now_utc() + Duration::minutes(POP_EXP_MINUTES);
    assert_eq!(pop.body.expires_at.unix_timestamp(), exp.unix_timestamp());

    let claims = sample_claims_sdjwt();

    println!("Claims: {:?}", claims);

    let vc = issuer
        .issue_credential(&request, &claims, nonce, None)
        .await
        .unwrap();

    println!("Credential {:?}", &vc);

    let vc_meta = DefaultMetadataProcessor::resolve_metadata(&vc, key_metadata).unwrap();
    let _ = holder.store_credential(&vc, &vc_meta).await.unwrap();

    println!("Present proof...");

    let input_descriptor: InputDescriptor = serde_json::from_value(json!({
        "id": "Identity-1",
        "name": "Identity VC",
        "purpose": "We want a resident card",
        "format": {
            "dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256", "EdDSA"],
                "kb-jwt_alg_values": ["ES256", "EdDSA"],
            }
        },
        "constraints": {
            "fields": [
                {
                    "path": ["$.vct"],
                    "filter": {
                        "type": "string",
                        "const": "https://credentials.example.com/identity_credential"
                    }
                },
                {
                    "path": ["$.given_name"],
                }
            ]
        }
    }))
    .unwrap();

    let nonce = LocalNonceHandler::default().generate().await.unwrap();

    let vp_res = holder
        .create_presentation_auto(&nonce, VERIFIER_ID, &input_descriptor.try_into().unwrap())
        .await;

    let vp = vp_res.unwrap();
    println!("Presentation {:?}", vp);

    let ver_res = verifier
        .verify_presentation(
            &nonce,
            &vp,
            &ReqwestClientBuilder::new().insecure().build().unwrap(),
        )
        .await;
    assert!(ver_res.is_ok());

    let res_claims = ver_res.unwrap();
    println!("Presentation claims {:?}", res_claims);

    // tests claim expiration. It was set during issuer creation
    let exp = time::OffsetDateTime::now_utc() + Duration::days(CLAIM_EXP_DAYS);
    let diff = res_claims["exp"].as_int().unwrap().to_owned() - exp.unix_timestamp();
    assert!(diff < 5);

    assert!(res_claims.get("given_name").is_some());
    // should not return family_name as it is not selectively disclosed
    assert!(res_claims.get("family_name").is_none());
    assert!(res_claims.get("dob").is_some());
}

#[tokio::test]
async fn bbs_plus_credential_issuance_and_presentation_verification() {
    // Initialization
    let holder_kms = LocalKms::new();
    let nonce_gen = LocalNonceHandler::default();

    let issuer = build_issuer_with_bbs_plus_credential_profile().await;
    let holder = build_holder(holder_kms.clone()).await;
    let verifier = build_verifier(VERIFIER_ID);

    println!("Issue credential...");

    let offer = issuer.offer_credential("LdpVc_cred", None);
    let offer = offer.unwrap();

    let nonce = Some(nonce_gen.generate().await.unwrap());
    let (did, key_metadata, _) = create_did_keymetadata_keyhandle(&holder_kms).await;
    let request = holder
        .request_credential(&offer, nonce.clone(), &key_metadata)
        .await;
    let request = request.unwrap();

    let claims = serde_json::from_value(json!(
        {
            "id": did,
            "alumniOf": "The School of Examples",
            "degree": "Bachelor of Schools",
        }
    ))
    .unwrap();

    println!("Claims: {}", serde_json::to_string_pretty(&claims).unwrap());

    let vc = issuer
        .issue_credential(&request, &claims, nonce, None)
        .await
        .unwrap();

    println!("Credential {}", serde_json::to_string_pretty(&vc).unwrap());

    let vc_meta = DefaultMetadataProcessor::resolve_metadata(&vc, key_metadata).unwrap();
    let _ = holder.store_credential(&vc, &vc_meta).await.unwrap();

    println!("Present proof...");

    let input_descriptor: InputDescriptor = serde_json::from_value(json!({
        "id": "Identity-1",
        "name": "University Degree",
        "purpose": "We want a alumni attestation",
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
                },
                {
                    "path": ["$.credentialSubject.alumniOf"],
                },
                {
                    "path": ["$.issuer"],
                }
            ]
        }
    }))
    .unwrap();

    let nonce = LocalNonceHandler::default().generate().await.unwrap();

    let vp_res = holder
        .create_presentation_auto(&nonce, VERIFIER_ID, &input_descriptor.try_into().unwrap())
        .await;

    let vp = vp_res.unwrap();
    println!(
        "Presentation {}",
        serde_json::to_string_pretty(&vp).unwrap()
    );

    let ver_res = verifier
        .verify_presentation(
            &nonce,
            &vp,
            &ReqwestClientBuilder::new().insecure().build().unwrap(),
        )
        .await;
    assert!(ver_res.is_ok());

    let res_claims = ver_res.unwrap();
    println!(
        "Presentation claims {}",
        serde_json::to_string_pretty(&res_claims).unwrap()
    );

    let vp = res_claims["verifiableCredential"]
        .as_object()
        .unwrap()
        .clone();

    let cred_subject = vp["credentialSubject"].as_object().unwrap().clone();

    assert!(cred_subject.contains_key("alumniOf"));
    assert!(!cred_subject.contains_key("degree"));
}

#[tokio::test]
async fn credential_issuance_and_status_verification() {
    // Initialization
    let (mut server_list_server, status_list_url) = run_status_list_server().await;

    let holder_kms = LocalKms::new();
    let nonce_gen = LocalNonceHandler::default();

    let status_issuer = build_status_issuer(status_list_url.clone()).await;
    let issuer = build_issuer_with_sd_jwt_credential_profile().await;
    let holder = build_holder(holder_kms.clone()).await;
    let verifier = build_verifier(VERIFIER_ID);

    // Status list issuance and serving
    println!("Status list issuance...\n");
    let status_list_jwt = issue_status_list_with_revoked_indexes(&status_issuer, vec![]).await;
    println!("Status list token JWT: {}\n", status_list_jwt);
    serve_status_list(&mut server_list_server, status_list_jwt);

    println!("Issue credential...");

    let offer = issuer.offer_credential(SCOPE, None);
    let offer = offer.unwrap();

    let nonce = Some(nonce_gen.generate().await.unwrap());
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&holder_kms).await;
    let request = holder
        .request_credential(&offer, nonce.clone(), &key_metadata)
        .await;
    let request = request.unwrap();

    let claims = sample_claims_sdjwt();

    println!("Claims: {:?}", claims);

    let status_info = agent_sdk::vc::core::CredentialStatusInfo::TokenStatusList {
        idx: 1,
        uri: status_list_url,
    };
    let vc = issuer
        .issue_credential(&request, &claims, nonce, Some(status_info))
        .await
        .unwrap();

    println!("Credential {:?}", &vc);

    let vc_meta = DefaultMetadataProcessor::resolve_metadata(&vc, key_metadata).unwrap();
    let _ = holder.store_credential(&vc, &vc_meta).await.unwrap();

    println!("Present proof...");

    let input_descriptor: InputDescriptor = serde_json::from_value(json!({
        "id": "Identity-1",
        "name": "Identity VC",
        "purpose": "We want a resident card",
        "format": {
            "dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256", "EdDSA"],
                "kb-jwt_alg_values": ["ES256", "EdDSA"],
            }
        },
        "constraints": {
            "fields": [
                {
                    "path": ["$.vct"],
                    "filter": {
                        "type": "string",
                        "const": "https://credentials.example.com/identity_credential"
                    }
                },
                {
                    "path": ["$.given_name"],
                },
                {
                    "path": ["$.family_name"],
                }
            ]
        }
    }))
    .unwrap();

    let nonce = LocalNonceHandler::default().generate().await.unwrap();

    let vp_res = holder
        .create_presentation_auto(&nonce, VERIFIER_ID, &input_descriptor.try_into().unwrap())
        .await;

    let vp = vp_res.unwrap();
    println!("Presentation {:?}", vp);

    let ver_res = verifier
        .verify_presentation(
            &nonce,
            &vp,
            &ReqwestClientBuilder::new().insecure().build().unwrap(),
        )
        .await;
    assert!(ver_res.is_ok());

    let res_claims = ver_res.unwrap();
    println!("Presentation claims {:?}", res_claims);

    assert!(res_claims.get("given_name").is_some());
    assert!(res_claims.get("family_name").is_some());
    // should return not only requested claims, but all in credential
    assert!(res_claims.get("dob").is_some());

    let http_client = ReqwestClientBuilder::new().insecure().build().unwrap();
    let cred_status = verifier
        .obtain_credential_status(&vp, &http_client)
        .await
        .unwrap();

    println!("{:?}", cred_status);
}

async fn build_issuer_with_sd_jwt_credential_profile() -> impl Issuer {
    // Initialization
    println!("Issuer creating...");

    let kms = LocalKms::new();
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;

    let metadata = IssuerMetadata {
        issuer_id: key_metadata.did_url.to_string(),
        cred_defs: vec![CredentialDefinition {
            cred_def_id: SCOPE.into(),
            format: vc::VCFormat::SdJwtVc,
            claims: Default::default(),
            supported_proofs: Some(HashMap::from([(PopFormat::Jwt, vec![Alg::ES256])])),
            supported_signing_algs: Some(vec![Alg::ES256]),
            display: None,
            protocol_data: Some(CredentialDefinitionData::SdJwt {
                vct: VC_TYPE.to_string(),
                disclosures: vec!["$.given_name".to_owned(), "$.family_name".to_owned()],
                lifetime: Duration::days(CLAIM_EXP_DAYS),
            }),
            key_metadata,
        }],
        protocol_data: None,
    };

    IssuerService::new(kms, metadata, UniversalResolver::default())
}

async fn build_issuer_with_bbs_plus_credential_profile() -> impl Issuer {
    // Initialization
    println!("Issuer creating...");

    let kms = LocalKms::new();
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::Bls12381, kms::CreateOptions {})
        .await
        .unwrap();

    let did = DIDKey::generate(kh.clone()).unwrap();

    let vm = UniversalResolver::default()
        .resolve_into_any_verification_method(DIDBuf::from_str(&did).unwrap().as_did())
        .await
        .unwrap()
        .unwrap()
        .id;

    let key_metadata = KeyMetadata {
        did_url: vm.to_string(),
        kid,
    };

    let metadata = IssuerMetadata {
        issuer_id: vm.to_string(),
        cred_defs: vec![CredentialDefinition {
            cred_def_id: "LdpVc_cred".into(),
            format: vc::VCFormat::LdpVc,
            claims: Default::default(),
            supported_proofs: Some(HashMap::from([(PopFormat::Jwt, vec![Alg::ES256])])),
            supported_signing_algs: Some(vec![Alg::BBS]),
            display: None,
            protocol_data: Some(CredentialDefinitionData::Ldp {
                contexts: vec![
                    "https://www.w3.org/ns/credentials/v2".to_string(),
                    "https://www.w3.org/ns/credentials/examples/v2".to_string(),
                ],
                vc_types: vec![
                    "VerifiableCredential".to_string(),
                    "AlumniCredential".to_string(),
                ],
                credential_id: Some("urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f".to_string()),
                lifetime: Duration::days(5 * 365),
            }),
            key_metadata,
        }],
        protocol_data: None,
    };

    IssuerService::new(kms, metadata, UniversalResolver::default())
}

async fn build_status_issuer(status_list_url: Url) -> impl StatusIssuer {
    // Initialization
    println!("Status issuer creating...");

    let kms = LocalKms::new();
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;

    let metadata = StatusIssuerMetadata {
        issuer_id: "123456".to_string(),
        supported_status_lists: vec![StatusListDefinition {
            id: "test".to_string(),
            format: StatusListFormat::StatusListTokenJwt(
                vc::status_formats::status_list_token_jwt::SLMetadata {
                    statuses_nr: 32,
                    status_list_url,
                    status_size: StatusSize::try_from(1u8).unwrap(),
                },
            ),
            key_metadata,
        }],
    };

    StatusIssuerService::new(kms, metadata)
}

async fn build_holder(kms: LocalKms) -> impl Holder {
    // Initialization
    println!("Holder creating...");

    let vault = InMemVault::new();

    HolderService::new(
        kms,
        vault,
        HolderMetadata {
            client_id: "client_id".into(),
            pop_lifetime: time::Duration::minutes(POP_EXP_MINUTES),
        },
        UniversalResolver::default(),
        Arc::new(ReqwestClientBuilder::new().insecure().build().unwrap()),
    )
}

fn build_verifier(id: &str) -> impl Verifier {
    VerifierService::new(id, UniversalResolver::default())
}

async fn run_status_list_server() -> (mockito::ServerGuard, Url) {
    let server = mockito::Server::new_async().await;
    let port_idx = server.url().rfind(':').unwrap() + 1;
    let port = &server.url()[port_idx..];

    let status_list_url_string = format!("http://localhost:{port}{STATUS_LIST_PATH}");
    let status_list_url = Url::try_from(status_list_url_string.as_str()).unwrap();
    println!("status list URL: {status_list_url_string}");

    (server, status_list_url)
}

fn serve_status_list(server: &mut mockito::ServerGuard, status_list: String) {
    server
        .mock("GET", STATUS_LIST_PATH)
        .with_status(200)
        .with_header("content-type", "application/statuslist+jwt")
        .with_body(status_list)
        .create();
}

async fn issue_status_list_with_revoked_indexes(
    status_issuer: &impl StatusIssuer,
    revoked: Vec<usize>,
) -> String {
    let mut statuses = VCStatuses::new();

    for idx in revoked {
        statuses.set(idx, VCStatus::Invalid);
    }

    let status_list = status_issuer
        .issue_status_list("test", VCStatusesData::StatusListToken(statuses))
        .await
        .unwrap();

    let crate::vc::StatusList::StatusListTokenJwt(status_list) = status_list;

    status_list
}
