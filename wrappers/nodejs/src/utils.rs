use crate::vc::core::{JsCredential, JsCredentialMetadata, JsKeyMetadata};
use crate::vc::JsonObject;
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::{Credential, HasClaims};
use napi_derive::napi;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::Level;
use url::Url;

pub fn from_json_object<T: DeserializeOwned>(object: JsonObject) -> napi::Result<T> {
    Ok(serde_json::from_value(serde_json::Value::Object(object))?)
}

pub fn to_json_object<T: Serialize>(value: T) -> napi::Result<JsonObject> {
    let value = serde_json::to_value(value)?;

    match value {
        serde_json::Value::Object(object) => Ok(object),
        _ => Err(napi::Error::from_reason(format!(
            "{value} cannot be represented as a JSON object"
        ))),
    }
}

pub fn parse_url_arg(url: &str) -> napi::Result<Url> {
    url.parse().map_err(|err| {
        napi::Error::new(napi::Status::InvalidArg, format!("Url parse error: {err}"))
    })
}

#[napi]
pub async fn resolve_metadata(
    credential: JsCredential,
    metadata: JsKeyMetadata,
) -> Result<JsCredentialMetadata, napi::Error> {
    let credential = credential.try_into()?;
    let metadata = metadata.into();
    let result = DefaultMetadataProcessor::resolve_metadata(&credential, metadata).unwrap();
    result.try_into()
}

#[napi(ts_return_type = "Promise<Claims>")]
pub async fn parse_claims(credential: JsCredential) -> Result<JsonObject, napi::Error> {
    let credential: Credential = credential.try_into()?;
    let claims = credential
        .parse_claims()
        .map_err(|err| napi::Error::from_reason(err.to_string()))?;
    to_json_object(claims)
}

#[napi]
pub enum TracingLogFormat {
    Full,
    Compact,
    Pretty,
    Json,
}

#[napi]
pub enum TracingLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<TracingLogLevel> for Level {
    fn from(value: TracingLogLevel) -> Self {
        match value {
            TracingLogLevel::Trace => Level::TRACE,
            TracingLogLevel::Debug => Level::DEBUG,
            TracingLogLevel::Info => Level::INFO,
            TracingLogLevel::Warn => Level::WARN,
            TracingLogLevel::Error => Level::ERROR,
        }
    }
}

#[napi]
pub async fn enable_logs(format: Option<TracingLogFormat>, level: Option<TracingLogLevel>) {
    let level_filter = level.map(|lvl| lvl.into()).unwrap_or(Level::INFO);
    let subscriber_builder = tracing_subscriber::fmt().with_env_filter(level_filter.as_str());

    match format {
        None | Some(TracingLogFormat::Full) => subscriber_builder.init(),
        Some(TracingLogFormat::Compact) => subscriber_builder.compact().init(),
        Some(TracingLogFormat::Pretty) => subscriber_builder.pretty().init(),
        Some(TracingLogFormat::Json) => subscriber_builder.json().init(),
    };
}
