use base64::{DecodeError, Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn encode(vec: Vec<u8>) -> String {
    URL_SAFE_NO_PAD.encode(vec.as_slice())
}

pub fn decode(payload: &str) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(payload)
}