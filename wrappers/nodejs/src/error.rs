use napi_derive::napi;
use serde::{Deserialize, Serialize};

pub trait IntoNapiError {
    fn into_napi_error(self) -> napi::Error;
}

impl<T> IntoNapiError for T
where
    T: Into<EncodableError>,
{
    fn into_napi_error(self) -> napi::Error {
        napi::Error::from_reason(self.into().encode())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[napi(object, js_name = "EqusSdkError")]
pub struct EncodableError {
    pub code: String,
    pub message: String,
    /// Structured data of the error, by code: for `IssuerNotTrusted`, the `IssuerTrust` of every
    /// presented credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[napi(ts_type = "unknown")]
    pub details: Option<serde_json::Value>,
}

impl EncodableError {
    pub fn new(code: String, message: String) -> Self {
        Self {
            code,
            message,
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn encode(self) -> String {
        serde_json::to_string(&self).unwrap_or(format!(
            "Failed to encode error to json. Original code: {}. Original message: {}.",
            self.code, self.message
        ))
    }
}
