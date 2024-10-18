use crate::kms::NativeKms;
use crate::vc::core::{JsCredential, JsCredentialMetadata, JsDIDAndKeyMetadata, JsKeyMetadata};
use crate::vc::JsonObject;
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::DIDResolver;
use agent_sdk::kms;
use agent_sdk::kms::Kms;
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use napi_derive::napi;
use serde::de::DeserializeOwned;
use serde::Serialize;
use url::Url;

pub fn from_json_object<T: DeserializeOwned>(object: JsonObject) -> napi::Result<T> {
    Ok(serde_json::from_value(serde_json::Value::Object(object))?)
}

pub fn to_json_object<T: Serialize>(value: T) -> napi::Result<JsonObject> {
    let value = serde_json::to_value(value)?;

    match value {
        serde_json::Value::Object(object) => Ok(object),
        _ => Err(napi::Error::from_reason(format!(
            "{value} cannot be represented as a JSON object"
        ))),
    }
}

pub fn parse_url_arg(url: &str) -> napi::Result<Url> {
    url.parse().map_err(|err| {
        napi::Error::new(napi::Status::InvalidArg, format!("Url parse error: {err}"))
    })
}

#[cfg(debug_assertions)]
#[napi]
pub async fn create_did_and_key_metadata(kms: &NativeKms) -> JsDIDAndKeyMetadata {
    let did_key = DIDKey::new();

    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions {})
        .await
        .unwrap();

    let did = did_key.generate(kh).unwrap();

    let vm = did_key.resolve_verification_method(&did).await.unwrap().id;

    JsDIDAndKeyMetadata {
        did,
        key_metadata: JsKeyMetadata { did_url: vm, kid },
    }
}

#[napi]
pub async fn resolve_metadata(
    credential: JsCredential,
    metadata: JsKeyMetadata,
) -> Result<JsCredentialMetadata, napi::Error> {
    let credential = credential.try_into()?;
    let metadata = metadata.into();
    let result = DefaultMetadataProcessor::resolve_metadata(&credential, metadata).unwrap();
    result.try_into()
}

#[napi]
pub async fn enable_logs() {
    tracing_subscriber::fmt::init();
}
