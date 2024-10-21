use agent_sdk::crypto::{Alg, Key, Signer, SigningKey, Verifier, VerifyingKey, JWK};
use agent_sdk::kms::{CreateOptions, KeyHandle, KeyID, KeyType, Kms};
use agent_sdk::{crypto, kms};
use async_trait::async_trait;
use napi_derive::napi;
use std::sync::Arc;

mod js;
mod native;
#[cfg(debug_assertions)]
pub mod test;
mod unified;

pub use js::JsKms;
pub use native::NativeKms;
pub use unified::UnifiedKms;

#[derive(Clone)]
pub struct KeyHandleWrapper(Arc<dyn SigningKey>, Arc<dyn VerifyingKey>);

impl SigningKey for KeyHandleWrapper {}

impl Key for KeyHandleWrapper {
    fn pub_key(&self) -> crypto::Result<Vec<u8>> {
        self.0.pub_key()
    }

    fn jwk(&self) -> Option<JWK> {
        self.0.jwk()
    }
}

#[async_trait]
impl Signer for KeyHandleWrapper {
    fn alg(&self) -> Alg {
        self.0.alg()
    }

    async fn sign(&self, payload: &[u8]) -> crypto::Result<Vec<u8>> {
        self.0.sign(payload).await
    }
}

impl VerifyingKey for KeyHandleWrapper {}

#[async_trait]
impl Verifier for KeyHandleWrapper {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> crypto::Result<()> {
        self.1.verify(data, signature).await
    }
}

impl KeyHandle for KeyHandleWrapper {}

#[derive(Clone)]
struct KmsWrapper<KH: KeyHandle>(Arc<dyn Kms<KH>>);

#[async_trait]
impl<KH: KeyHandle + 'static> Kms<KeyHandleWrapper> for KmsWrapper<KH> {
    async fn create(&self, kt: KeyType, opts: CreateOptions) -> kms::Result<KeyID> {
        self.0.create(kt, opts).await
    }

    async fn get(&self, kid: &KeyID) -> kms::Result<KeyHandleWrapper> {
        let key_handle = self.0.get(kid).await?;
        let arc = Arc::new(key_handle);

        Ok(KeyHandleWrapper(arc.clone(), arc.clone()))
    }
}

#[napi(js_name = "KeyType")]
pub enum JsKeyType {
    Ed25519,
    P256,
}

impl From<JsKeyType> for KeyType {
    fn from(value: JsKeyType) -> Self {
        match value {
            JsKeyType::Ed25519 => KeyType::Ed25519,
            JsKeyType::P256 => KeyType::P256,
        }
    }
}

impl TryFrom<KeyType> for JsKeyType {
    type Error = napi::Error;

    fn try_from(value: KeyType) -> napi::Result<Self> {
        match value {
            KeyType::Ed25519 => Ok(JsKeyType::Ed25519),
            KeyType::P256 => Ok(JsKeyType::P256),
            _ => Err(napi::Error::from_reason(format!(
                "Unsupported key type {value}"
            ))),
        }
    }
}
