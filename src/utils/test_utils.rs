use crate::did::didkey::DIDKey;
use crate::did::{DIDResolver, DID};
use crate::inmem::kms::LocalKms;
use crate::kms;
use crate::kms::Kms;
use crate::vc::core::KeyMetadata;

pub async fn create_did_and_key_metadata(kms: &LocalKms) -> (DID, KeyMetadata) {
    let didkey = DIDKey::new();

    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = didkey.generate(kh).unwrap();

    let vm = didkey.resolve_verification_method(&did).await.unwrap().id;

    (did, KeyMetadata { kid, did_url: vm })
}
