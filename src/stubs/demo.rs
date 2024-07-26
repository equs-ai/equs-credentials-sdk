use std::io;
use std::io::Write;
use std::str::FromStr;

use oauth2::{AccessToken, TokenResponse};
use oid4vci::core::profiles::w3c::CredentialDefinition;
use oid4vci::core::profiles::w3c::jwt::Request;
use oid4vci::metadata::CredentialUrl;
use oid4vci::openidconnect::IssuerUrl;
use serde_json::json;

use crate::core_::kms::{KeyType, Kms};
use crate::core_::pop::{GenerateOptions, ProofOfPossession, VerifyOptions};
use crate::core_::storage::Storage;
use crate::core_::vault::Vault;
use crate::core_::vc::API;
use crate::exchange::oid4vc::vci::{Holder, Issuer};
use crate::exchange::oid4vc::vci::CredentialResult;
use crate::impls::did::didkey::DIDKey;
use crate::impls::pop::jwt_pop::JwtProofOfPossession;
use crate::impls::storage::inmem::InMemStorage;
use crate::impls::vault::inmem::InMemVault;
use crate::impls::vc::sd_jwt_vc::{SdJwtAPI, VCMetadata, VPMetadata};
use crate::stubs::*;

pub(crate) async fn low_level_demo() {
    // Holder init
    let master_key = "abracadabra";
    let mut h_kms = LocalKms::new();
    let mut h_vault = InMemVault::new();
    let _ = h_vault.open(master_key);
    let mut h_store = InMemStorage::new();

    let h_kid = h_kms.create(&KeyType::Ed25519, kms::CreateOptions {}).await.unwrap();
    let h_kh = h_kms.get(&h_kid).await.unwrap();
    let h_did = DIDKey::new().generate(h_kh.clone()).unwrap();
    let h_did_url = DIDURL::from_str(&h_did).unwrap();
    let _ = h_store.put(h_did_url.clone().to_string(), h_kid.clone());

    // Issuer init
    let mut i_kms = LocalKms::new();
    let i_vault = InMemVault::new();

    let i_kid = i_kms.create(&KeyType::Ed25519, kms::CreateOptions {}).await.unwrap();
    let i_kh = i_kms.get(&i_kid).await.unwrap();
    let i_did = DIDKey::new().generate(i_kh).unwrap();
    let i_did_url = DIDURL::from_str(&i_did).unwrap();

    // Holder's generation of PoP
    let nonce = Nonce::new_random();
    let pop_kh = h_kms.get(&h_kid).await.unwrap();
    let pop = JwtProofOfPossession::generate(
        &h_did_url,
        pop_kh,
        nonce.clone(),
        GenerateOptions {
            cred_iss_id: i_did_url.to_string(),
            ..Default::default()
        },
    ).await.unwrap();

    // VC issuing
    // verifying ProofOfPossession
    let _ = JwtProofOfPossession::verify(
        pop,
        nonce.clone(),
        VerifyOptions {
            cred_iss_id: i_did_url.to_string(),
            ..Default::default()
        },
    ).await.unwrap();

    // claims and holder did are known
    let claims = serde_json::json!({
        "sub": &h_did.clone(),
        "name":"John Doe"
    });
    let claims = claims.as_object().unwrap().clone();

    let handle = i_kms.get(&i_kid).await.unwrap();
    let creds = SdJwtAPI::create_vc(
        claims,
        (&i_did_url, handle),
        (&h_did_url, h_kh.clone()),
        VCMetadata { disclosures: vec!["$.name"], ..Default::default() },
    ).await.unwrap();


    // creds transferred to Holder ...
    let _ = h_vault.store_credential(vc::Credential::SdJwt(creds)).await;

    // generate presentation
    let criteria = FindCriteria {}; // later to be inferred from exchange level Proof Presentations
    let found_creds = h_vault.find_credentials(criteria).await.unwrap();
    // Choose appropriate credential
    let chosen = found_creds.get(0).unwrap();
    let chosen_kid = h_store.get(&resolve_holder_did(&chosen).to_string()).await.unwrap();
    let chosen_kh = h_kms.get(&chosen_kid).await.unwrap();
    let presentation = match chosen {
        vc::Credential::SdJwt(cred) => SdJwtAPI::create_vp(
            cred,
            (&h_did_url,chosen_kh),
            Nonce::new_random(),
            "verifier-12345",
            VPMetadata { disclosures: json!({"name":"true"}).as_object().unwrap().to_owned() },
        ).await.unwrap(),
        // other presentations possible
        _ => panic!(""),
    };

    // verify presentation
    let _ = SdJwtAPI::verify_vp(
        &presentation,
        Nonce::new_random(),
        "verifier-12345",
        vc::VerifyOptions {},
    ).await.unwrap();
}


pub(crate) async fn exchange_demo() {
    // Issuer init
    let kms = LocalKms::new();
    let metadata = oid4vc::vci::IssuerMetadata::new(
        IssuerUrl::new("https://issuer.com".into()).unwrap(),
        CredentialUrl::new("https://issuer.com/credential".into()).unwrap(),
        // define the credentials to be supported
        vec![],
    );
    let issuer = _Issuer::new(kms, metadata);

    // Out-of-band:
    // Get the code from Authorization Server to be associated with targeted offer
    let code = "123";
    let cred_ids = vec![String::from("UniversityDegreeCredential")];
    let offer = issuer.offer_pre_authz_flow(code, &cred_ids).await.unwrap();

    // Holder init
    // Out-of-band:
    // Offer sent to the holder/ Offer put under `credential_offer_uri`
    let holder = _Holder::from_offer(CredentialOffer::Value { credential_offer: offer }).await.unwrap();

    // Pre-authorized code flow
    let response = holder.pre_authorized_flow(&cred_ids).await.unwrap();
    // OR using Authorized Code flow
    let _ = holder.authz_code_flow(&cred_ids, |url: Url| {
        // Only for demonstration purposes
        println!("Auth URL: {}", url.to_owned().to_string());
        print!("Please enter an authorization code: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read auth code");
        input
    }).await.unwrap();

    // ... Authorization server returned token and other fields
    let token = response.access_token().secret().clone();

    // Creating suitable request
    let req = CredentialRequest::JWTVC(Request::new(CredentialDefinition::new(cred_ids.clone())));

    // No proof of possession for demo's brevity
    let res = holder.request(AccessToken::new(token.clone()), req, None, None, None).await.unwrap();

    // ... in the same time the following Issuer's methods invoked

    // let _ = issuer.validate_request(req.clone());
    // let _ = issuer.validate_token(AccessToken::new(token.clone()));
    //let _ = issuer.verify_proof(...)
    // let vc = issuer.issue_credential(req, ...)

    match res {
        CredentialResult::Deferred { transaction_id } => {
            let _ = holder.deferred(AccessToken::new(token.clone()), transaction_id).await.unwrap();
        }
        CredentialResult::Credential { credential, notification_id } => {
            let mut vault = InMemVault::new();

            let _ = vault.store_credential(credential).await.unwrap();
        }
    }
}


fn resolve_holder_did(cred: &vc::Credential) -> DIDURL {
    todo!()
}