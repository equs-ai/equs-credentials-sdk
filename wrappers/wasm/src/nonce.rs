use crate::utils;
use agent_sdk::nonce::{GenerateSnafu, InvalidateSnafu, Nonce, ValidateSnafu};
use async_trait::async_trait;
use js_sys::{Array, Boolean, JsString};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "NonceHandler")]
    pub type NonceHandler;

    #[wasm_bindgen(structural, method, catch, js_name = generate)]
    pub async fn generate(this: &NonceHandler) -> Result<JsString, JsValue>;

    #[wasm_bindgen(structural, method, catch, js_name = validate)]
    pub async fn validate(this: &NonceHandler, nonce: JsString) -> Result<Boolean, JsValue>;

    #[wasm_bindgen(structural, method, catch, js_name = invalidate)]
    pub async fn invalidate(this: &NonceHandler, nonces: Array) -> Result<JsValue, JsValue>;
}

pub(crate) struct JsNonceHandler(NonceHandler);

impl JsNonceHandler {
    pub fn new(handler: NonceHandler) -> Self {
        Self(handler)
    }
}

#[async_trait(?Send)]
impl agent_sdk::nonce::NonceHandler for JsNonceHandler {
    async fn generate(&self) -> agent_sdk::nonce::Result<Nonce> {
        let js_nonce = self.0.generate().await.map_err(|e| {
            GenerateSnafu {
                details: format!("Failed to generate nonce: {}", utils::js_value_to_string(e)),
            }
            .build()
        })?;
        Ok(Nonce::from_secret(String::from(js_nonce)))
    }

    async fn validate(&self, nonce: &Nonce) -> agent_sdk::nonce::Result<bool> {
        let js_nonce = JsString::from(nonce.secret().to_string());
        let validated = self.0.validate(js_nonce).await.map_err(|e| {
            let msg = format!("Failed to validate nonce: {}", utils::js_value_to_string(e));
            ValidateSnafu { details: msg }.build()
        })?;
        Ok(validated.value_of())
    }

    async fn invalidate(&self, nonces: &[Nonce]) -> agent_sdk::nonce::Result<()> {
        let js_nonces: Array = nonces
            .iter()
            .map(|nonce| JsValue::from_str(nonce.secret()))
            .collect();

        self.0.invalidate(js_nonces).await.map_err(|e| {
            let msg = format!(
                "Failed to invalidate nonces: {}",
                utils::js_value_to_string(e)
            );
            InvalidateSnafu { details: msg }.build()
        })?;

        Ok(())
    }
}
