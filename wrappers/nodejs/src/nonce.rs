use agent_sdk::nonce;
use agent_sdk::nonce::{GenerateSnafu, Nonce, NonceHandler, ValidateSnafu};
use async_trait::async_trait;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;

/// An async generic `NonceHandler` interface for generating nonce  .
///
/// Supports `generate` operation.
///
/// @property {() => Promise<string>} generate - method to create nonce
///
#[derive(Clone)]
#[napi(js_name = "NonceHandler", object, object_to_js = false)]
pub struct JsNonceHandler {
    #[napi(ts_type = "() => Promise<string>")]
    pub generate: ThreadsafeFunction<(), ErrorStrategy::Fatal>,
    #[napi(ts_type = "(nonce: string) => Promise<boolean>")]
    pub validate: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
}

#[async_trait]
impl NonceHandler for JsNonceHandler {
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

    async fn validate(&self, nonce: &Nonce) -> nonce::Result<bool> {
        let promise: Promise<bool> = self
            .validate
            .call_async(nonce.secret().to_owned())
            .await
            .map_err(|err| {
                ValidateSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            ValidateSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

#[cfg(debug_assertions)]
pub mod test_utils {
    use super::JsNonceHandler;
    use agent_sdk::nonce::NonceHandler;
    use napi_derive::napi;

    #[napi]
    pub struct NonceHandlerTestHelper(JsNonceHandler);

    #[napi]
    impl NonceHandlerTestHelper {
        #[napi(constructor)]
        pub fn new(nonce_handler: JsNonceHandler) -> Self {
            NonceHandlerTestHelper(nonce_handler)
        }

        #[napi]
        pub async fn generate(&self) -> String {
            self.0.generate().await.unwrap().secret().to_string()
        }

        #[napi]
        pub async fn validate(&self, nonce: String) -> bool {
            self.0
                .validate(&agent_sdk::nonce::Nonce::from_secret(nonce))
                .await
                .unwrap()
        }
    }
}
