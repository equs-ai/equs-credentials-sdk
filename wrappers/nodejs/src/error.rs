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
}

impl EncodableError {
    pub fn new(code: String, message: String) -> Self {
        Self { code, message }
    }

    pub fn encode(self) -> String {
        serde_json::to_string(&self).unwrap_or(format!(
            "Failed to encode error to json. Original code: {}. Original message: {}.",
            self.code, self.message
        ))
    }
}
