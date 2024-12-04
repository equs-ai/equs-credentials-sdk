#![allow(dead_code)]

mod utils;

use std::collections::HashMap;
use std::str::FromStr;

use agent_sdk::crypto::Alg;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::nonce::LocalNonceGenerator;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::nonce::NonceGenerator;
use agent_sdk::vc;
use agent_sdk::vc::core::HolderService;
use agent_sdk::vc::core::IssuerService;
use agent_sdk::vc::core::VerifierService;
use agent_sdk::vc::core::{
    CredentialDefinition, CredentialDefinitionData, Holder, HolderMetadata, Issuer, IssuerMetadata,
    PopFormat, Verifier,
};
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::presentation_exchange::InputDescriptor;
use serde_json::json;
use ssi::did::DIDURL;
use utils::fixtures::{sample_claims_sdjwt, SCOPE, VC_TYPE, VERIFIER_ID};
use utils::helpers::create_did_keymetadata_keyhandle;

#[tokio::test]
async fn credential_issuance_and_presentation_verification() {
    // Initialization
    let holder_kms = LocalKms::new();
    let nonce_gen = LocalNonceGenerator::default();

    let issuer = build_issuer().await;
    let holder = build_holder(holder_kms.clone()).await;
    let verifier = build_verifier(VERIFIER_ID);

    println!("Issue credential...");

    let offer = issuer.offer_credential(SCOPE, None);
    let offer = offer.unwrap();

    let nonce = nonce_gen.generate().await.unwrap();
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&holder_kms).await;
    let request = holder
        .request_credential(&offer, &nonce, &key_metadata)
        .await;
    let request = request.unwrap();

    let claims = sample_claims_sdjwt();

    println!("Claims: {:?}", claims);

    let vc = issuer
        .issue_credential(&request, &claims, &nonce)
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
            "vc+sd-jwt": {
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

    let nonce = LocalNonceGenerator::default().generate().await.unwrap();

    let vp_res = holder
        .create_presentation_auto(&nonce, VERIFIER_ID, &input_descriptor.try_into().unwrap())
        .await;

    let vp = vp_res.unwrap();
    println!("Presentation {:?}", vp);

    let ver_res = verifier.verify_presentation(&nonce, &vp).await;
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
