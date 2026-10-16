use crate::kms::{JsBIP32Params, JsECDH1PUParams, JsECDHESParams, JsKeyType};
use crate::vc::core::JsAlg;
use equs_sdk::crypto::{Key, Signer, Verifier};
use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::kms::{BIP32Params, CreateOptions, DerivativeKms, ECDH1PUParams, ECDHESParams, Kms};
use napi::bindgen_prelude::Uint8Array;
use napi::{Error, Result};
use napi_derive::napi;

#[napi]
pub struct InMemKeyHandle {
    inner: equs_sdk::inmem::kms::KeyHandle,
    pub jwk: Option<String>,
}

#[napi]
impl InMemKeyHandle {
    pub fn new(handle: equs_sdk::inmem::kms::KeyHandle) -> Self {
        let jwk = handle
            .jwk()
            .and_then(|value| serde_json::to_string(&value).ok());

        Self { inner: handle, jwk }
    }

    #[napi(getter)]
    pub fn pub_key(&self) -> Result<Vec<u8>> {
        self.inner
            .pub_key()
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }

    #[napi(getter)]
    pub fn alg(&self) -> Result<JsAlg> {
        self.inner.alg().try_into()
    }

    #[napi]
    pub async fn sign(&self, payload: &[u8]) -> Result<Uint8Array> {
        self.inner
            .sign(payload)
            .await
            .map(Into::into)
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.inner
            .verify(data, signature)
            .await
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }
}

#[napi]
pub struct InMemKms(LocalKms);

#[napi]
impl InMemKms {
    #[napi(constructor)]
    pub fn new() -> Self {
        let kms = LocalKms::new();
        InMemKms(kms)
    }

    #[napi]
    pub async fn derive_ecdhes(&self, params: JsECDHESParams) -> Result<Vec<u8>> {
        let derivation: ECDHESParams = params.into();
        self.0
            .derive(derivation)
            .await
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn derive_ecdh1pu(&self, params: JsECDH1PUParams) -> Result<Vec<u8>> {
        let derivation: ECDH1PUParams = params.into();
        self.0
            .derive(derivation)
            .await
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn derive_bip32(&self, params: JsBIP32Params) -> Result<String> {
        let derivation: BIP32Params = params.try_into()?;
        self.0
            .derive(derivation)
            .await
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn create(&self, kt: JsKeyType) -> Result<String> {
        self.0
            .create(kt.into(), CreateOptions::default())
            .await
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn get(&self, kid: String) -> Result<InMemKeyHandle> {
        self.0
            .get(&kid)
            .await
            .map(InMemKeyHandle::new)
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn get_by_public_key(&self, public_key: &[u8]) -> Result<InMemKeyHandle> {
        self.0
            .get_by_public_key(public_key)
            .await
            .map(InMemKeyHandle::new)
            .map_err(|err| Error::from_reason(format!("{err:?}")))
    }
}

impl Default for InMemKms {
    fn default() -> Self {
        let kms = LocalKms::new();
        InMemKms(kms)
    }
}
