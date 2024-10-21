use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::DIDResolver;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use napi::Either;
use napi_derive::napi;

use crate::kms::{JsKms, NativeKms, UnifiedKms};
use crate::vc::core::JsKeyMetadata;

#[napi]
pub async fn create_key_metadata(kms: Either<&NativeKms, JsKms>) -> JsKeyMetadata {
    _create_key_metadata(kms.into()).await
}

async fn _create_key_metadata(kms: UnifiedKms) -> JsKeyMetadata {
    let did_key = DIDKey::new();

    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = did_key.generate(kh).unwrap();

    let vm = did_key.resolve_verification_method(&did).await.unwrap().id;

    JsKeyMetadata { did_url: vm, kid }
}

#[napi]
pub fn wrap_js_kms(kms: JsKms) -> NativeKms {
    NativeKms::from(kms)
}
