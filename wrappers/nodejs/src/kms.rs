use crate::utils::to_result_string;
use crate::vc::core::JsAlg;
use agent_sdk::crypto::{Alg, Key, Signer, SigningKey, Verifier, VerifyingKey, JWK};
use agent_sdk::kms::{CreateOptions, KeyHandle, KeyID, KeyType, Kms};
use agent_sdk::{crypto, kms};
use async_trait::async_trait;
use napi_derive::napi;
use std::sync::Arc;

#[napi]
#[derive(Clone)]
pub struct NativeKeyHandle(Arc<dyn SigningKey>, Arc<dyn VerifyingKey>);

#[napi]
impl NativeKeyHandle {
    pub fn from<KH: KeyHandle + 'static>(key_handle: KH) -> NativeKeyHandle {
        let key_handle = Arc::new(key_handle);
        NativeKeyHandle(key_handle.clone(), key_handle.clone())
    }

    #[napi]
    pub fn pub_key(&self) -> napi::Result<Vec<u8>> {
        self.0
            .pub_key()
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub fn jwk(&self) -> Option<String> {
        self.0.jwk().and_then(|value| to_result_string(&value).ok())
    }

    #[napi]
    pub fn alg(&self) -> napi::Result<JsAlg> {
        self.0.alg().try_into()
    }

    #[napi]
    pub async fn sign(&self, payload: &[u8]) -> napi::Result<Vec<u8>> {
        self.0
            .sign(payload)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn verify(&self, data: &[u8], signature: &[u8]) -> napi::Result<()> {
        self.1
            .verify(data, signature)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }
}

impl SigningKey for NativeKeyHandle {}

impl Key for NativeKeyHandle {
    fn pub_key(&self) -> crypto::Result<Vec<u8>> {
        self.0.pub_key()
    }

    fn jwk(&self) -> Option<JWK> {
        self.0.jwk()
    }
}

#[async_trait]
impl Signer for NativeKeyHandle {
    fn alg(&self) -> Alg {
        self.0.alg()
    }

    async fn sign(&self, payload: &[u8]) -> crypto::Result<Vec<u8>> {
        self.0.sign(payload).await
    }
}

impl VerifyingKey for NativeKeyHandle {}

#[async_trait]
impl Verifier for NativeKeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> crypto::Result<()> {
        self.1.verify(data, signature).await
    }
}

impl KeyHandle for NativeKeyHandle {}

#[derive(Clone)]
#[napi]
pub struct NativeKms(Arc<dyn Kms<NativeKeyHandle>>);

#[napi]
impl NativeKms {
    pub fn from<KMS: Kms<KH> + 'static, KH: KeyHandle + 'static>(kms: KMS) -> NativeKms {
        NativeKms(Arc::new(_KmsWrapper(Arc::new(kms))))
    }

    #[napi]
    pub async fn create(&self, kt: JsKeyType) -> napi::Result<String> {
        self.0
            .create(kt.into(), CreateOptions {})
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn get(&self, kid: String) -> napi::Result<NativeKeyHandle> {
        self.0
            .get(&kid)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }
}

#[async_trait]
impl Kms<NativeKeyHandle> for NativeKms {
    async fn create(&self, kt: KeyType, opts: CreateOptions) -> kms::Result<KeyID> {
        self.0.create(kt, opts).await
    }

    async fn get(&self, kid: &KeyID) -> kms::Result<NativeKeyHandle> {
        self.0.get(kid).await
    }
}

#[derive(Clone)]
struct _KmsWrapper<KH: KeyHandle>(Arc<dyn Kms<KH>>);

#[async_trait]
impl<KH: KeyHandle + 'static> Kms<NativeKeyHandle> for _KmsWrapper<KH> {
    async fn create(&self, kt: KeyType, opts: CreateOptions) -> kms::Result<KeyID> {
        self.0.create(kt, opts).await
    }

    async fn get(&self, kid: &KeyID) -> kms::Result<NativeKeyHandle> {
        let key_handle = self.0.get(kid).await?;

        Ok(NativeKeyHandle::from(key_handle))
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
