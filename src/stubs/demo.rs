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
    let h_did_result = _DIDCore::create(DIDMethod::DidKey, did::CreateOptions {}).await.unwrap();
    let h_did = h_did_result.did.unwrap();
    let _ = h_store.put(&h_did, &h_kid);

    // Issuer init
    let i_kms = _Kms::new();
    let i_vault = _Vault::new();

    let i_kid = i_kms.create(KeyType::ED25519, kms::CreateOptions {}).await.unwrap();
    let i_did_result = _DIDCore::create(DIDMethod::DidWeb, did::CreateOptions {}).await.unwrap();
    let i_did = i_did_result.did.unwrap();

    // VC issuing
    // claims and holder did are known
    let builder = _W3cBuilder {};
    let cred_material = CredentialMaterial::W3c(builder
        .subject_from_did(&h_did)
        .claims_from_json(serde_json::json!({"name":"John Doe"}))
        .build()
    );

    let handle = i_kms.get(i_kid).await.unwrap();
    let proof_preparation = DIDProof::new(i_did);
    let creds = _VC::generate(cred_material, proof_preparation, handle, ()).await.unwrap();

    // creds transferred to Holder ...
    let _ = h_vault.store_credential(creds).await;

    // generate presentation
    let criteria = FindCriteria {}; // later to be inferred from exchange level Proof Presentations
    let creds = h_vault.find_credentials(criteria).await.unwrap();

    let creds_with_signers = resolve_signers(creds, h_store, h_kms).await;

    let presentation = _VP::generate(creds_with_signers, ()).await.unwrap();

    // verify presentation
    let _ = _Verifier::validate(presentation, ()).await;
}

// Helpers
pub async fn resolve_signers(creds: Vec<Credential>, store: _KeyStorage, kms: _Kms) -> Vec<(Credential, _KeyHandle)> { todo!() }







