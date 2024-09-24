#![allow(dead_code)]

mod utils;

use std::collections::HashMap;
use std::str::FromStr;

use oid4vci::openidconnect::Nonce;
use serde_json::json;
use ssi::did::DIDURL;

use agent_sdk::crypto::Alg;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::vc;
use agent_sdk::vc::core::HolderService;
use agent_sdk::vc::core::IssuerService;
use agent_sdk::vc::core::VerifierService;
use agent_sdk::vc::core::{
    CredentialDefinition, CredentialDefinitionData, Holder, HolderMetadata, Issuer, IssuerMetadata,
    PopFormat, PresentationInput, Verifier,
};
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::SD_JWT_VC;

use utils::fixtures::{sample_claims, SCOPE, VC_TYPE, VERIFIER_ID};
use utils::helpers::create_did_keymetadata_keyhandle;

#[tokio::test]
async fn credential_issuance_and_presentation_verification() {
    // Initialization
    let holder_kms = LocalKms::new();

    let issuer = build_issuer().await;
    let holder = build_holder(holder_kms.clone()).await;
    let verifier = build_verifier(VERIFIER_ID);

    println!("Issue credential...");

    let offer = issuer.offer_credential(SCOPE, None);
    let offer = offer.unwrap();

    let nonce = Nonce::new_random();
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&holder_kms).await;
    let request = holder
        .request_credential(&offer, nonce.secret(), &key_metadata)
        .await;
    let request = request.unwrap();

    let claims = sample_claims();

    println!("Claims: {:?}", claims);

    let vc = issuer
        .issue_credential(&request, &claims, nonce.secret())
        .await
        .unwrap();

    println!("Credential {:?}", &vc);

    let vc_meta = DefaultMetadataProcessor::resolve_metadata(&vc, key_metadata).unwrap();
    let _ = holder.store_credential(&vc, &vc_meta).await.unwrap();

    println!("Present proof...");

    let presentation_input = PresentationInput {
        id: SCOPE.to_string(),
        type_: VC_TYPE.to_string(),
        format: SD_JWT_VC.to_string(),
        claims: json!({
           "given_name": true,
           "family_name": true,
        })
        .as_object()
        .unwrap()
        .to_owned(),
    };

    let nonce = Nonce::new_random();

    let vp_res = holder
        .create_presentation_auto(nonce.secret(), VERIFIER_ID, &presentation_input)
        .await;

    let vp = vp_res.unwrap();
    println!("Presentation {:?}", vp);

    let ver_res = verifier.verify_presentation(nonce.secret(), &vp).await;
    assert!(ver_res.is_ok());

    let res_claims = ver_res.unwrap();
    println!("Presentation claims {:?}", res_claims);
    let res_claims = res_claims.as_object().unwrap();

    assert!(res_claims.contains_key("given_name"));
    assert!(res_claims.contains_key("family_name"));
    // should return not only requested claims, but all in credential
    assert!(res_claims.contains_key("dob"));
}

async fn build_issuer() -> impl Issuer {
    // Initialization
    println!("Issuer creating...");

    let kms = LocalKms::new();
    let (did, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;
    let did_url = DIDURL::from_str(&did).unwrap();

    let metadata = IssuerMetadata {
        issuer_id: did_url.to_string(),
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
                lifetime: None,
            }),
            key_metadata,
        }],
        protocol_data: None,
    };

    IssuerService::new(kms, metadata)
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
        },
    )
}

fn build_verifier(id: &str) -> impl Verifier {
    VerifierService::new(id)
}
