use agent_sdk::nonce::NonceData;
use napi::{Error, Status};
use napi_derive::napi;
use time::{Duration, OffsetDateTime};

mod js;
mod native;
#[cfg(debug_assertions)]
pub mod test;
mod unified;

pub use js::JsNonceGenerator;
pub use native::NativeNonceGenerator;
pub use unified::UnifiedNonceGenerator;

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
