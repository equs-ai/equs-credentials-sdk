use std::io;
use std::io::Write;

use oauth2::{AccessToken, TokenResponse};
use oid4vci::core::profiles::w3c::CredentialDefinition;
use oid4vci::core::profiles::w3c::jwt::Request;
use oid4vci::metadata::CredentialUrl;
use oid4vci::openidconnect::IssuerUrl;

use crate::core_::did::{DIDCore, DIDMethod};
use crate::core_::kms::{KeyType, Kms};
use crate::core_::storage::Storage;
use crate::core_::vault::Vault;
use crate::core_::vc::API;
use crate::exchange::oid4vc::vci::{Holder, Issuer};
use crate::exchange::oid4vc::vci::CredentialResult;
use crate::impls::storage::inmem::InMemStorage;
use crate::impls::vault::inmem::InMemVault;
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
    let h_did_result = _DIDCore::create(DIDMethod::DidKey, h_kh, did::CreateOptions {}).await.unwrap();
    let h_did = h_did_result.did.unwrap();
    let h_did_url = DIDURL { did: h_did.clone(), path_abempty: String::from("/"), query: None, fragment: None };
    let _ = h_store.put(h_did_url.clone().to_string(), h_kid.clone());

    // Issuer init
    let mut i_kms = LocalKms::new();
    let i_vault = InMemVault::new();

    let i_kid = i_kms.create(&KeyType::Ed25519, kms::CreateOptions {}).await.unwrap();
    let i_kh = i_kms.get(&i_kid).await.unwrap();
    let i_did_result = _DIDCore::create(DIDMethod::DidWeb, i_kh, did::CreateOptions {}).await.unwrap();
    let i_did = i_did_result.did.unwrap();

    // Holder's generation of PoP
    let nonce = "iss_nonce";
    let pop_kh = h_kms.get(&h_kid).await.unwrap();
    let pop = _JwtProofOfPossessionAPI::generate(
        &h_did_url,
        pop_kh,
        String::from(nonce),
        i_did.clone(),
        None,
    ).await.unwrap();

    // VC issuing
    // verifying ProofOfPossession
    let _ = _JwtProofOfPossessionAPI::verify(pop, pop::VerifyOptions {}).await.unwrap();

    // claims and holder did are known
    let claims = serde_json::json!({
        "sub": &h_did.clone(),
        "name":"John Doe"
    });
    let claims = claims.as_object().unwrap().clone();

    let handle = i_kms.get(&i_kid).await.unwrap();
    let did_url = DIDURL { did: i_did.clone(), path_abempty: String::from("/"), query: None, fragment: None };
    let creds = _SdJwtAPI::create_vc(
        claims,
        handle,
        &did_url,
        VCMetadata { disclosures: vec![String::from("name")] },
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
        vc::Credential::SdJwt(cred) => _SdJwtAPI::create_vp(
            cred,
            chosen_kh,
            String::from("nonce-"),
            "verifier-12345",
            &h_did_url,
            VPMetadata { disclosures: vec![String::from("name")] },
        ).await.unwrap(),
        // other presentations possible
        _ => panic!(""),
    };

    // verify presentation
    let _ = _SdJwtAPI::verify_vp(&presentation, vc::VerifyOptions {}).await;
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