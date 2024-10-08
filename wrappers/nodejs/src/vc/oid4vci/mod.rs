use napi::{Error, Result, Status};
use napi_derive::napi;
use time::{Duration, OffsetDateTime};

pub mod builder;
pub mod holder;
pub mod issuer;

#[napi(object)]
pub struct NonceData {
    pub nonce: String,
    pub expires_in: Option<i64>,
    pub created: i64,
}

impl TryFrom<NonceData> for agent_sdk::nonce::NonceData {
    type Error = Error;

    fn try_from(value: NonceData) -> Result<Self> {
        let nonce = serde_json::from_str(&value.nonce)
            .map_err(|err| Error::new(Status::InvalidArg, format!("Nonce parsing error: {err}")))?;

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

impl TryFrom<agent_sdk::nonce::NonceData> for NonceData {
    type Error = Error;

    fn try_from(value: agent_sdk::nonce::NonceData) -> Result<Self> {
        let nonce = serde_json::to_string(&value.value).map_err(|err| {
            Error::new(
                Status::GenericFailure,
                format!("Nonce parsing error: {err}"),
            )
        })?;

        let created = value.created.unix_timestamp();
        let expires_in = value.expires_in.map(|value| value.whole_seconds());

        Ok(Self {
            nonce,
            expires_in,
            created,
        })
    }
}
