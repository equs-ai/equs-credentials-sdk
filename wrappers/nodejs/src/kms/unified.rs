use agent_sdk::kms::{CreateOptions, KeyID, KeyType, Kms};
use async_trait::async_trait;
use napi::Either;
use std::sync::Arc;

use crate::kms::js::JsKeyHandle;
use crate::kms::{JsKms, KeyHandleWrapper, NativeKms};

#[derive(Clone)]
pub enum UnifiedKms {
    Js(JsKms),
    Native(NativeKms),
}

#[async_trait]
impl Kms<KeyHandleWrapper> for UnifiedKms {
    async fn create(&self, kt: KeyType, opts: CreateOptions) -> agent_sdk::kms::Result<KeyID> {
        match self {
            UnifiedKms::Js(js) => js.create(kt, opts).await,
            UnifiedKms::Native(native) => native.inner().create(kt, opts).await,
        }
    }

    async fn get(&self, kid: &KeyID) -> agent_sdk::kms::Result<KeyHandleWrapper> {
        match self {
            UnifiedKms::Js(js) => js.get(kid).await.map(Into::into),
            UnifiedKms::Native(native) => native.inner().get(kid).await,
        }
    }
}

impl From<Either<&NativeKms, JsKms>> for UnifiedKms {
    fn from(value: Either<&NativeKms, JsKms>) -> Self {
        match value {
            Either::A(native) => UnifiedKms::Native(native.clone()),
            Either::B(js) => UnifiedKms::Js(js),
        }
    }
}

impl From<JsKeyHandle> for KeyHandleWrapper {
    fn from(key_handle: JsKeyHandle) -> KeyHandleWrapper {
        let key_handle = Arc::new(key_handle);
        KeyHandleWrapper(key_handle.clone(), key_handle.clone())
    }
}
