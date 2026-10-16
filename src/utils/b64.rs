use crate::vc::oid4vp::HashAlgorithm;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{DecodeError, Engine};
use bip32::secp256k1::sha2;
use bip32::secp256k1::sha2::Digest;
use tracing::Level;
use tracing::instrument;

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn encode(vec: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(vec)
}

#[instrument(
    level = Level::TRACE,
    err(),
    ret(),
)]
pub fn decode(payload: &str) -> Result<Vec<u8>, DecodeError> {
    URL_SAFE_NO_PAD.decode(payload)
}

pub fn get_hash_and_base64(input: String, alg: HashAlgorithm) -> String {
    let hash = match alg {
        HashAlgorithm::Sha256 => sha2::Sha256::digest(input.as_bytes()).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(input.as_bytes()).to_vec(),
        HashAlgorithm::Sha512 => sha2::Sha512::digest(input.as_bytes()).to_vec(),
    };
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use crate::utils::b64::{decode, encode};

    const PAYLOAD_SRC: &str = "just a payload to test";
    const PAYLOAD_B64: &str = "anVzdCBhIHBheWxvYWQgdG8gdGVzdA";

    #[test]
    fn encode_works_correctly() {
        let encoded = encode(PAYLOAD_SRC.as_bytes());

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
