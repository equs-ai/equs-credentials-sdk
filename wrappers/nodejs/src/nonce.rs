use agent_sdk::nonce;
use agent_sdk::nonce::{GenerateSnafu, Nonce, NonceData, NonceGenerator};
use async_trait::async_trait;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi::{Error, Status};
use napi_derive::napi;
use time::{Duration, OffsetDateTime};

/// An interface containing nonce with created time and duration.
#[napi(js_name = "NonceData", object)]
pub struct JsNonceData {
    pub nonce: String,
    pub expires_in: Option<i64>,
    pub created: i64,
}

impl TryFrom<JsNonceData> for NonceData {
    type Error = Error;

    fn try_from(value: JsNonceData) -> napi::Result<Self> {
        let nonce = serde_json::from_value(serde_json::Value::String(value.nonce))?;

        let created = OffsetDateTime::from_unix_timestamp(value.created).map_err(|err| {
            Error::new(Status::InvalidArg, format!("Incorrect created time: {err}"))
        })?;

        let expires_in = value.expires_in.map(Duration::seconds);

        Ok(Self {
            value: nonce,
            expires_in,
            created,
        })
    }
}

impl From<NonceData> for JsNonceData {
    fn from(value: NonceData) -> Self {
        let nonce = value.value.secret().to_string();

        let created = value.created.unix_timestamp();
        let expires_in = value.expires_in.map(|value| value.whole_seconds());

        Self {
            nonce,
            expires_in,
            created,
        }
    }
}

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

#[cfg(debug_assertions)]
pub mod test_utils {
    use super::JsNonceGenerator;
    use agent_sdk::nonce::NonceGenerator;
    use napi_derive::napi;

    #[napi]
    pub struct NonceGeneratorTestHelper(JsNonceGenerator);

    #[napi]
    impl NonceGeneratorTestHelper {
        #[napi(constructor)]
        pub fn new(nonce_generator: JsNonceGenerator) -> Self {
            NonceGeneratorTestHelper(nonce_generator)
        }

        #[napi]
        pub async fn generate(&self) -> String {
            self.0.generate().await.unwrap().secret().to_string()
        }
    }
}
