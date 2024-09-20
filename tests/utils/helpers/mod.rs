pub(crate) mod oid4vci;

use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::{DIDResolver, DID};
use agent_sdk::inmem::kms::{KeyHandle, LocalKms};
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::vc::core::KeyMetadata;

pub async fn create_did_keymetadata_keyhandle(kms: &LocalKms) -> (DID, KeyMetadata, KeyHandle) {
    let didkey = DIDKey::new();

    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = didkey.generate(kh.clone()).unwrap();

    let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

    (did, KeyMetadata { kid, did_url: vm }, kh)
}
