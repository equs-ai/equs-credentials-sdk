# nodejs/src — Context

## Purpose
Root Rust source crate for the Equs SDK Node.js wrapper. Uses NAPI-RS (`#[napi]` macros) to compile to a native Node.js add-on (`.node` binary). Exposes the full Equs SDK surface — DID methods, VC issuance and presentation (OID4VCI/OID4VP), DIDComm V2 messaging, KMS, vault, HTTP client, and nonce handling — as TypeScript-typed native classes and functions.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| `lib.rs` | Crate root; declares all public and private modules; re-exports `enable_logs`, `parse_claims`, `resolve_metadata` from `utils`. |
| `error.rs` | `EncodableError` (NAPI object with `code` and `message`) and `IntoNapiError` trait; all domain errors are serialized to JSON strings through this mechanism. |
| `http.rs` | `JsHttpClient` (callback-based `HttpClient` impl using ThreadsafeFunction) and `ReqwestHttpClient` (concrete reqwest-backed client exposed as a NAPI class). Includes HTTP method/request/response type conversions. |
| `kms.rs` | `JsKms` (callback-based `Kms` impl), `JsKeyHandle` (callback-based key handle satisfying `Key`/`Signer`/`Verifier`), key type and parameter types (`JsKeyType`, `JsECDHESParams`, `JsECDH1PUParams`, `JsBIP32Params`). Also `create_key_metadata` helper. |
| `vault.rs` | `JsVault` (callback-based `Vault` impl), `JsCredentialEntry`, `JsVaultPagination`, `JsCredentialsFindResult`, `JsFindVCsFailReason`. |
| `nonce.rs` | `JsNonceHandler` (callback-based `NonceHandler` impl for generate, validate and invalidate). |
| `utils.rs` | `from_json_object`/`to_json_object` serde helpers, `parse_url_arg`, `resolve_metadata`, `parse_claims`, `enable_logs` (tracing setup), `TracingLogFormat`/`TracingLogLevel` enums. |
| `did/` | DID method utilities and universal resolver — see [did/CLAUDE.md](did/CLAUDE.md) |
| `didcomm/` | DIDComm V2 envelope service — see [didcomm/CLAUDE.md](didcomm/CLAUDE.md) |
| `inmem/` | In-memory KMS, vault, and nonce implementations — see [inmem/CLAUDE.md](inmem/CLAUDE.md) |
| `vc/` | VC core, OID4VCI, OID4VP, and status formats — see [vc/CLAUDE.md](vc/CLAUDE.md) |

## Key types / traits
- `JsKms` — Callback-based `Kms<JsKeyHandle>` and `JweDecrypt` implementation driven by JS promises.
- `JsKeyHandle` — Callback-based `Key` + `Signer` + `Verifier` driven by JS promises.
- `JsVault` — Callback-based `Vault` implementation driven by JS promises.
- `JsHttpClient` — Callback-based `HttpClient` driven by JS promises.
- `ReqwestHttpClient` — Concrete reqwest HTTP client exposed directly to Node.js.
- `JsNonceHandler` — Callback-based nonce generator, validator and invalidator.
- `EncodableError` — Structured error serialized as JSON string for all NAPI error payloads.

## Dependencies
- Depends on: `equs_sdk` (all modules), `napi`/`napi-derive`, `async-trait`, `serde_json`, `tracing`/`tracing-subscriber`
- Used by: Node.js consumers via the compiled `.node` add-on; `demos/nodejs/`

## Constraints
- The `inmem` module is gated behind `#[cfg(any(test, feature = "in-memory"))]` in the Equs SDK core but is always compiled in the Node.js wrapper.
- DIDComm is non-wasm only; this wrapper is native and has no wasm constraints.
- ThreadsafeFunction callbacks require the event loop to remain alive; callers must ensure the Node.js runtime is not shut down while async operations are in flight.
