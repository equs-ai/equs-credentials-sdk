use agent_sdk::nonce::{Nonce, NonceData, NonceGenerator};
use async_trait::async_trait;
use napi::{Error, Status};
use napi_derive::napi;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

#[derive(Clone)]
#[napi]
pub struct NativeNonceGenerator(Arc<dyn NonceGenerator>);

impl NativeNonceGenerator {
    pub fn from<NG: NonceGenerator + 'static>(nonce_generator: NG) -> NativeNonceGenerator {
        let nonce_generator = Arc::new(nonce_generator);
        NativeNonceGenerator(nonce_generator)
    }
}

#[async_trait]
impl NonceGenerator for NativeNonceGenerator {
    async fn generate(&self) -> agent_sdk::nonce::Result<Nonce> {
        self.0.generate().await
    }

    async fn with_expiration(&self, expiration: Duration) -> agent_sdk::nonce::Result<NonceData> {
        self.0.with_expiration(expiration).await
    }
}

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
