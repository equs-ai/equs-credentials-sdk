use crate::core_::did::{DIDCore, DIDMethod};
use crate::core_::kms::{KeyType, Kms};
use crate::core_::vault::{Storage, Vault};
use crate::core_::vc::API;
use crate::core_::vc::sd_jwt_vc::SdJwtAPI;
use crate::stubs::*;

pub(crate) async fn low_level_demo() {
    // Holder init
    let master_key = "abracadabra";
    let h_kms = _Kms::new();
    let h_vault = _Vault::new();
    let _ = h_vault.open(master_key);
    let h_store = _KeyStorage::new();

    let h_kid = h_kms.create(KeyType::ED25519, kms::CreateOptions {}).await.unwrap();
    let h_kh = h_kms.get(&h_kid).await.unwrap();
    let h_did_result = _DIDCore::create(DIDMethod::DidKey, h_kh, did::CreateOptions {}).await.unwrap();
    let h_did = h_did_result.did.unwrap();
    let h_did_url = DIDURL { did: h_did.clone(), path_abempty: String::from("/"), query: None, fragment: None };
    let _ = h_store.put(&h_did_url, &h_kid);

    // Issuer init
    let i_kms = _Kms::new();
    let i_vault = _Vault::new();

    let i_kid = i_kms.create(KeyType::ED25519, kms::CreateOptions {}).await.unwrap();
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
    let chosen_kid = h_store.get(&resolve_holder_did(&chosen)).await.unwrap();
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

pub(crate) async fn exchange_demo() {}


fn resolve_holder_did(cred: &vc::Credential) -> DIDURL {
    todo!()
}