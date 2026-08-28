# utils — Context

## Purpose
A grab-bag of general-purpose helper modules shared across all SDK components: encoding, time bridging, JSON-path utilities, JWK conversions, HTTP constants, serde extras, log sanitization, wasm compatibility shims, and X.509 trust verification.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports all sub-modules and provides the small `contains_any` slice helper. |
| `b64.rs` | URL-safe no-padding base64 `encode`/`decode`, plus `get_hash_and_base64` (SHA-256/384/512 → base64). |
| `chrono_time_mapping.rs` | Bidirectional conversion traits (`TryFromChrono`, `TryIntoTime`, `TryFromTime`, `TryIntoChrono`) between `chrono::DateTime<Utc>` and `time::OffsetDateTime`. |
| `data_size.rs` | `DataSize` enum (`Bytes`, `KBytes`, `MBytes`, `GBytes`) with `From<DataSize> for usize`. |
| `http.rs` | MIME-type string constants, `MimeType` enum, `generate_post_req` builder, and `mock_http*` test helpers for `MockHttpClient`. |
| `json.rs` | JSON-path traversal (`find_json_element`), construction (`paths_to_json`), pointer conversion, and VC claim flattening (`claims_to_json_path`). |
| `jwk.rs` | `crypto::Key` impl for `ssi::JWK`; conversions between `ssi` / `jsonwebtoken` / `one-core` JWK types. |
| `logs.rs` | `sanitize_log_msg` — strips non-alphanumeric characters and appends a base64 copy to prevent log injection. |
| `serde.rs` | `Helpers` trait on `Claims` (`put_str`, `put_dt`); custom serde (de)serializers for `Duration` and `OffsetDateTime`; `accumulate_claim_names`. |
| `test_utils.rs` | Test-only DID/key-handle factories (`create_did_and_key_metadata`, etc.), stub `MockKey`, and `MockJweKms`. |
| `wasm.rs` | `WasmNotSend` / `WasmNotSync` marker traits — `Send`/`Sync`-equivalent on native, no-op on wasm32. |
| `x509_truststore.rs` | `Truststore<T>` — validates X.509 PEM chains up to a trusted anchor whose own PEM it holds (keyed by SKI) and resolves issuer `DecodingKey` for SD-JWT-VC verification. |

## Key types / traits
- `MimeType` — enum of allowed MIME types with `as_str()`.
- `DataSize` — human-readable size that converts to `usize` bytes.
- `TryFromChrono` / `TryIntoTime` / `TryFromTime` / `TryIntoChrono` — time-library bridge traits.
- `WasmNotSend` / `WasmNotSync` — platform-adaptive `Send`/`Sync` markers.
- `Truststore<T: CertificateValidator>` — X.509 chain validator implementing `sd_jwt_rs::resolver::KeyResolver`.
  Trust requires a verified signature over the chain's topmost certificate by a held anchor; a chain's own
  Authority Key Identifier only selects which anchor to try and never grants trust by itself.
- `sanitize_log_msg` — log injection prevention helper.

## Dependencies
- Depends on: `crate::crypto`, `crate::kms`, `crate::vc::claims`, `crate::http`, `ssi`, `jsonwebtoken`, `one-core` / `one-core-portable`, `base64`, `chrono`, `time`, `serde_json`, `serde`, `tracing`.
- Used by: virtually every other SDK module.

## Constraints
- `x509_truststore` is `#[cfg(not(target_arch = "wasm32"))]`.
- `test_utils` is `#[cfg(test)]` only.
- `jwk::from_one_core_public_key_jwk_jsonwebtoken_jwk` is `#[cfg(not(target_arch = "wasm32"))]`.
- All other sub-modules are wasm-compatible.
