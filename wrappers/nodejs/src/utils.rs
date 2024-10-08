use serde::de::DeserializeOwned;
use serde::Serialize;
use url::Url;

pub fn parse_string_arg<T: DeserializeOwned>(value: &str) -> napi::Result<T> {
    serde_json::from_str(value).map_err(|err| napi::Error::new(napi::Status::InvalidArg, err))
}

pub fn parse_url_arg(url: &str) -> napi::Result<Url> {
    url.parse().map_err(|err| {
        napi::Error::new(napi::Status::InvalidArg, format!("Url parse error: {err}"))
    })
}

pub fn to_result_string<T: Serialize>(value: &T) -> napi::Result<String> {
    serde_json::to_string(&value).map_err(|err| napi::Error::from_reason(err.to_string()))
}
