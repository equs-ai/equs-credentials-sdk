use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{DecodeError, Engine};
use tracing::{instrument, Level};

#[instrument(
    level = Level::TRACE,
    ret(level = Level::TRACE)
)]
pub fn encode(vec: Vec<u8>) -> String {
    URL_SAFE_NO_PAD.encode(vec.as_slice())
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(level = Level::TRACE)
)]
pub fn decode(payload: &str) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(payload)
}
