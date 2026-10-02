//! Decoding helpers for the round-trip suite.
//!
//! These read a compact JWS without verifying it — the assertions that follow
//! are about which claims a builder emits, and the signature is checked by the
//! SDK verifier in the same test.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

fn segment(jwt: &str, index: usize) -> Value {
    let raw = jwt
        .split('.')
        .nth(index)
        .unwrap_or_else(|| panic!("compact JWS has no segment {index}: {jwt}"));
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .unwrap_or_else(|e| panic!("segment {index} is not base64url: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("segment {index} is not JSON: {e}"))
}

/// The decoded, unverified JOSE header.
pub fn decode_header(jwt: &str) -> Value {
    segment(jwt, 0)
}

/// The decoded, unverified payload.
pub fn decode_payload(jwt: &str) -> Value {
    segment(jwt, 1)
}
