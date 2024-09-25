use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{DecodeError, Engine};
use tracing::{instrument, Level};

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn encode(vec: Vec<u8>) -> String {
    URL_SAFE_NO_PAD.encode(vec.as_slice())
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(),
)]
pub fn decode(payload: &str) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(payload)
}

#[cfg(test)]
mod tests {
    use crate::utils::b64::{decode, encode};

    const PAYLOAD_SRC: &str = "just a payload to test";
    const PAYLOAD_B64: &str = "anVzdCBhIHBheWxvYWQgdG8gdGVzdA";

    #[test]
    fn encode_works_correctly() {
        let encoded = encode(PAYLOAD_SRC.as_bytes().to_vec());

        assert_eq!(encoded, PAYLOAD_B64);
    }

    #[test]
    fn decode_works_correctly() {
        let decoded = decode(PAYLOAD_B64).unwrap();

        assert_eq!(decoded, PAYLOAD_SRC.as_bytes().to_vec());
    }

    #[test]
    fn decode_fails_on_invalid_b64() {
        assert!(decode("not-a-b64!").is_err());
    }
}
