use crate::crypto::{Alg, KeyType};
use crate::utils;
use async_trait::async_trait;
use equs_sdk::crypto::{JWK, Key, Signer, SigningKey, SigningSnafu, Verifier, VerifyingKey};
use equs_sdk::kms::{CreateOptions, CreationSnafu, KeyID, ResolvingSnafu};
use std::ops::Deref;
use std::rc::Rc;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "KeyHandle")]
    pub type KeyHandle;

    #[wasm_bindgen(structural, method, getter, js_name = pubKey)]
    pub fn pub_key(this: &KeyHandle) -> Option<js_sys::Uint8Array>;

    #[wasm_bindgen(structural, method, getter)]
    pub fn jwk(this: &KeyHandle) -> Option<js_sys::JsString>;

    #[wasm_bindgen(structural, method, getter)]
    pub fn alg(this: &KeyHandle) -> Alg;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn sign(this: &KeyHandle, payload: &[u8]) -> Result<js_sys::Uint8Array, JsValue>;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn verify(this: &KeyHandle, data: &[u8], signature: &[u8]) -> Result<(), JsValue>;

    #[wasm_bindgen(typescript_type = "Kms")]
    pub type Kms;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn create(this: &Kms, kt: KeyType) -> Result<js_sys::JsString, JsValue>;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn get(this: &Kms, kid: &str) -> Result<KeyHandle, JsValue>;

    #[wasm_bindgen(structural, method, catch, js_name = getByPublicKey)]
    pub async fn get_by_public_key(this: &Kms, pk: &[u8]) -> Result<KeyHandle, JsValue>;
}

#[derive(Clone)]
pub(crate) struct JsKeyHandle(Rc<KeyHandle>);

impl JsKeyHandle {
    pub fn new(key_handle: KeyHandle) -> Self {
        Self(Rc::new(key_handle))
    }
}

#[async_trait(?Send)]
impl SigningKey for JsKeyHandle {}

impl Key for JsKeyHandle {
    fn pub_key(&self) -> equs_sdk::crypto::Result<Vec<u8>> {
        self.0
            .pub_key()
            .map(|v| v.to_vec())
            .ok_or_else(|| equs_sdk::crypto::KeyNotSupportedSnafu { type_: "public" }.build())
    }

    fn jwk(&self) -> Option<JWK> {
        self.0
            .jwk()
            .and_then(|jwk| jwk.as_string())
            .and_then(|jwk| serde_json::from_str(&jwk).ok())
    }
}

#[async_trait(?Send)]
impl Signer for JsKeyHandle {
    fn alg(&self) -> equs_sdk::crypto::Alg {
        let alg = self.0.alg();

        // TODO: Maybe we should change the method signature to return a Result
        //     so that errors during getting algorithm are properly handled.
        utils::convert_to_rust_object(alg).unwrap()
    }

    async fn sign(&self, payload: &[u8]) -> equs_sdk::crypto::Result<Vec<u8>> {
        self.0.sign(payload).await.map(|v| v.to_vec()).map_err(|e| {
            SigningSnafu {
                details: utils::js_value_to_string(e),
            }
            .build()
        })
    }
}

#[async_trait(?Send)]
impl VerifyingKey for JsKeyHandle {}

#[async_trait(?Send)]
impl Verifier for JsKeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> equs_sdk::crypto::Result<()> {
        self.0.verify(data, signature).await.map_err(|e| {
            SigningSnafu {
                details: format!("{:?}", e),
            }
            .build()
        })
    }
}

impl equs_sdk::kms::KeyHandle for JsKeyHandle {}

#[derive(Clone)]
pub(crate) struct JsKms(Rc<Kms>);

impl JsKms {
    pub fn new(kms: Kms) -> Self {
        Self(Rc::new(kms))
    }
}

#[async_trait(?Send)]
impl equs_sdk::kms::Kms<JsKeyHandle> for JsKms {
    async fn create(
        &self,
        kt: equs_sdk::kms::KeyType,
        _: CreateOptions,
    ) -> equs_sdk::kms::Result<KeyID> {
        let kt = utils::convert_to_opaque_object_unchecked(kt.to_string()).unwrap();

        let js_kid = self.0.create(kt).await.map_err(|e| {
            CreationSnafu {
                details: utils::js_value_to_string(e),
            }
            .build()
        })?;

        js_kid.as_string().ok_or_else(|| {
            CreationSnafu {
                details: format!("Key ID conversion failed: {js_kid}"),
            }
            .build()
        })
    }

    async fn get(&self, kid: &KeyID) -> equs_sdk::kms::Result<JsKeyHandle> {
        let key_handle = self.0.get(kid.deref().into()).await.map_err(|e| {
            ResolvingSnafu {
                details: utils::js_value_to_string(e),
            }
            .build()
        })?;

        Ok(JsKeyHandle::new(key_handle))
    }

    async fn get_by_public_key(&self, public_key: &[u8]) -> equs_sdk::kms::Result<JsKeyHandle> {
        let key_handle = self.0.get_by_public_key(public_key).await.map_err(|e| {
            ResolvingSnafu {
                details: utils::js_value_to_string(e),
            }
            .build()
        })?;

        Ok(JsKeyHandle::new(key_handle))
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use crate::crypto::{Alg, KeyType};
    use crate::kms::{JsKeyHandle, JsKms, KeyHandle};
    use crate::utils;
    use equs_sdk::crypto::{Key, Signer, Verifier};
    use equs_sdk::kms;
    use equs_sdk::kms::{CreateOptions, KeyID, Kms};
    use std::rc::Rc;
    use std::str::FromStr;
    use wasm_bindgen::JsError;
    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen]
    struct KeyHandleTestHelper(JsKeyHandle);

    #[wasm_bindgen]
    impl KeyHandleTestHelper {
        #[wasm_bindgen(constructor)]
        pub fn new(key_handle: KeyHandle) -> Self {
            KeyHandleTestHelper(JsKeyHandle(Rc::new(key_handle)))
        }

        #[wasm_bindgen(getter, js_name = pubKey)]
        pub fn pub_key(&self) -> Vec<u8> {
            self.0.pub_key().unwrap()
        }

        #[wasm_bindgen(getter)]
        pub fn jwk(&self) -> Option<String> {
            self.0.jwk().map(|jwk| jwk.to_string())
        }

        #[wasm_bindgen(getter)]
        pub fn alg(&self) -> Alg {
            let alg = self.0.alg();

            utils::convert_to_opaque_object_unchecked(alg).unwrap()
        }

        #[wasm_bindgen]
        pub async fn sign(&self, payload: &[u8]) -> Vec<u8> {
            self.0.sign(payload).await.unwrap()
        }

        #[wasm_bindgen]
        pub async fn verify(&self, data: &[u8], signature: &[u8]) {
            self.0.verify(data, signature).await.unwrap()
        }
    }

    #[wasm_bindgen]
    struct KmsTestHelper(JsKms);

    #[wasm_bindgen]
    impl KmsTestHelper {
        #[wasm_bindgen(constructor)]
        pub fn new(kms: crate::kms::Kms) -> Self {
            KmsTestHelper(JsKms::new(kms))
        }

        #[wasm_bindgen]
        pub async fn create(&self, kt: KeyType) -> KeyID {
            let key_type_str: String = utils::convert_to_rust_object(kt).unwrap();

            let key_type = kms::KeyType::from_str(&key_type_str)
                .map_err(JsError::from)
                .unwrap();

            self.0
                .create(key_type, CreateOptions::default())
                .await
                .unwrap()
        }

        #[wasm_bindgen]
        pub async fn get(&self, kid: String) -> KeyHandleTestHelper {
            self.0.get(&kid).await.map(KeyHandleTestHelper).unwrap()
        }

        #[wasm_bindgen(js_name = getByPublicKey)]
        pub async fn get_by_public_key(&self, public_key: &[u8]) -> KeyHandleTestHelper {
            self.0
                .get_by_public_key(public_key)
                .await
                .map(KeyHandleTestHelper)
                .unwrap()
        }
    }
}
