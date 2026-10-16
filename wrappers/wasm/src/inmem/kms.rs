use crate::crypto::{Alg, KeyType};
use crate::utils;
use equs_sdk::crypto::{Key, Signer, Verifier};
use equs_sdk::inmem::kms::{KeyHandle, LocalKms};
use equs_sdk::kms;
use equs_sdk::kms::{CreateOptions, KeyID, Kms};
use std::str::FromStr;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct InMemKeyHandle(KeyHandle);

#[wasm_bindgen]
impl InMemKeyHandle {
    #[wasm_bindgen(getter)]
    pub fn alg(&self) -> Result<Alg, JsError> {
        let alg = self.0.alg();

        utils::convert_to_opaque_object_unchecked(alg)
    }

    #[wasm_bindgen]
    pub async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0
            .sign(payload)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }

    #[wasm_bindgen]
    pub async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), JsError> {
        self.0
            .verify(data, signature)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }

    #[wasm_bindgen(getter)]
    pub fn jwk(&self) -> Option<String> {
        self.0.jwk().map(|jwk| jwk.to_string())
    }

    #[wasm_bindgen(getter, js_name = pubKey)]
    pub fn pub_key(&self) -> Result<Vec<u8>, JsError> {
        self.0
            .pub_key()
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }
}

impl InMemKeyHandle {
    pub fn inner(&self) -> &KeyHandle {
        &self.0
    }
}

#[wasm_bindgen]
pub struct InMemKms(LocalKms);

#[wasm_bindgen]
impl InMemKms {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(LocalKms::new())
    }

    #[wasm_bindgen]
    pub async fn create(&self, kt: KeyType) -> Result<KeyID, JsError> {
        let key_type_str: String = utils::convert_to_rust_object(kt)?;

        let key_type = kms::KeyType::from_str(&key_type_str).map_err(JsError::from)?;

        self.0
            .create(key_type, CreateOptions::default())
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }

    #[wasm_bindgen]
    pub async fn get(&self, kid: String) -> Result<InMemKeyHandle, JsError> {
        self.0
            .get(&kid)
            .await
            .map(|kh| InMemKeyHandle(kh))
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }

    #[wasm_bindgen(js_name = getByPublicKey)]
    pub async fn get_by_public_key(&self, public_key: &[u8]) -> Result<InMemKeyHandle, JsError> {
        self.0
            .get_by_public_key(public_key)
            .await
            .map(|kh| InMemKeyHandle(kh))
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }
}

impl InMemKms {
    pub fn inner(&self) -> LocalKms {
        self.0.clone()
    }
}
