use crate::core_::did::{DIDCore, DIDMethod};
use crate::core_::kms::{KeyType, Kms};
use crate::core_::vault::{Storage, Vault};
use crate::core_::vc::{VC, Verifier, VP, W3cBuilder, W3cVcSubj};
use crate::stubs::{*};

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

    // VC issuing
    // claims and holder did are known
    let builder = _W3cBuilder {};
    let cred_material = CredentialMaterial::JWT_VC_JSON(builder
        .subject_from_did(&h_did)
        .claims_from_json(serde_json::json!({"name":"John Doe"}))
        .build()
    );

    let handle = i_kms.get(&i_kid).await.unwrap();
    let did_url = DIDURL { did: i_did.clone(), path_abempty: String::from("/"), query: None, fragment: None };
    let proof_preparation = DIDProof::new(did_url);
    let creds = _VC::generate(cred_material, proof_preparation, handle, ()).await.unwrap();

    // creds transferred to Holder ...
    let _ = h_vault.store_credential(creds).await;

    // generate presentation
    let criteria = FindCriteria {}; // later to be inferred from exchange level Proof Presentations
    let found_creds = h_vault.find_credentials(criteria).await.unwrap();
    // Choose appropriate credential
    let chosen = found_creds.get(0).unwrap();
    let chosen_kid = h_store.get(&resolve_holder_did(&chosen)).await.unwrap();
    let chosen_kh = h_kms.get(&chosen_kid).await.unwrap();
    let presentation = _VP::generate(chosen, chosen_kh, ()).await.unwrap();

    // verify presentation
    let _ = _Verifier::validate(&presentation, ()).await;
}

fn resolve_holder_did(cred: &Credential) -> DIDURL {
    todo!()
}