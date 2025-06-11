pub(crate) mod oid4vci;

use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DID, DIDResolver};
use agent_sdk::inmem::kms::{KeyHandle, LocalKms};
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::vc::core::KeyMetadata;
use ssi::dids::DIDBuf;
use std::str::FromStr;

pub async fn create_did_keymetadata_keyhandle(kms: &LocalKms) -> (DID, KeyMetadata, KeyHandle) {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh.clone()).unwrap();

    let vm = UniversalResolver::default()
        .resolve_into_any_verification_method(DIDBuf::from_str(&did).unwrap().as_did())
        .await
        .unwrap()
        .unwrap()
        .id;

    (
        did,
        KeyMetadata {
            kid,
            did_url: vm.to_string(),
        },
        kh,
    )
}
