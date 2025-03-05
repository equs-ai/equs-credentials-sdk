use agent_sdk::nonce;
use agent_sdk::nonce::{GenerateSnafu, Nonce, NonceGenerator};
use async_trait::async_trait;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;

/// An async generic `NonceGenerator` interface for generating nonce.
///
/// Supports `generate` operation.
///
/// @property {() => Promise<string>} generate - method to create nonce
///
#[derive(Clone)]
#[napi(js_name = "NonceGenerator", object, object_to_js = false)]
pub struct JsNonceGenerator {
    #[napi(ts_type = "() => Promise<string>")]
    pub generate: ThreadsafeFunction<(), ErrorStrategy::Fatal>,
}

#[async_trait]
impl NonceGenerator for JsNonceGenerator {
    async fn generate(&self) -> nonce::Result<Nonce> {
        let promise: Promise<String> = self.generate.call_async(()).await.map_err(|err| {
            GenerateSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        promise
            .await
            .and_then(|nonce| {
                serde_json::from_value(serde_json::Value::String(nonce)).map_err(Into::into)
            })
            .map_err(|err| {
                GenerateSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }
}
