use crate::kms::{JsKms, NativeKms, UnifiedKms};
use crate::vc::core::JsKeyMetadata;
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver};
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use napi::Either;
use napi_derive::napi;

#[napi]
pub async fn create_key_metadata(kms: Either<&NativeKms, JsKms>) -> JsKeyMetadata {
    _create_key_metadata(kms.into()).await
}

async fn _create_key_metadata(kms: UnifiedKms) -> JsKeyMetadata {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh).unwrap();

    let vm = UniversalResolver::default()
        .resolve_into_any_verification_method(&DIDBuf::from_string(did).unwrap())
        .await
        .unwrap()
        .unwrap()
        .id
        .as_did_url()
        .to_string();

    JsKeyMetadata { did_url: vm, kid }
}

#[napi]
pub fn wrap_js_kms(kms: JsKms) -> NativeKms {
    NativeKms::from(kms)
}
