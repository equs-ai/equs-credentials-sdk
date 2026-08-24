# Wrappers — Summary

## What this domain does
Exposes the Equs SDK Rust library to three foreign language targets via thin FFI/binding layers. Each wrapper translates Equs SDK's async Rust types to the idioms of its target ecosystem. No business logic lives here — wrappers only adapt types, handle errors, and re-export the SDK's public API surface.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| Node.js wrapper root | `wrappers/nodejs/src/` | [context](../wrappers/nodejs/src/CLAUDE.md) |
| Node.js — DID | `wrappers/nodejs/src/did/` | [context](../wrappers/nodejs/src/did/CLAUDE.md) |
| Node.js — DIDComm | `wrappers/nodejs/src/didcomm/` | [context](../wrappers/nodejs/src/didcomm/CLAUDE.md) |
| Node.js — In-memory | `wrappers/nodejs/src/inmem/` | [context](../wrappers/nodejs/src/inmem/CLAUDE.md) |
| Node.js — VC | `wrappers/nodejs/src/vc/` | [context](../wrappers/nodejs/src/vc/CLAUDE.md) |
| Node.js — VC Core | `wrappers/nodejs/src/vc/core/` | [context](../wrappers/nodejs/src/vc/core/CLAUDE.md) |
| Node.js — OID4VCI | `wrappers/nodejs/src/vc/oid4vci/` | [context](../wrappers/nodejs/src/vc/oid4vci/CLAUDE.md) |
| Node.js — OID4VP | `wrappers/nodejs/src/vc/oid4vp/` | [context](../wrappers/nodejs/src/vc/oid4vp/CLAUDE.md) |
| Node.js — Status formats | `wrappers/nodejs/src/vc/status_formats/` | [context](../wrappers/nodejs/src/vc/status_formats/CLAUDE.md) |
| UniFFI wrapper root | `wrappers/uniffi/src/` | [context](../wrappers/uniffi/src/CLAUDE.md) |
| UniFFI — DID | `wrappers/uniffi/src/did/` | [context](../wrappers/uniffi/src/did/CLAUDE.md) |
| UniFFI — In-memory | `wrappers/uniffi/src/inmem/` | [context](../wrappers/uniffi/src/inmem/CLAUDE.md) |
| UniFFI — VC | `wrappers/uniffi/src/vc/` | [context](../wrappers/uniffi/src/vc/CLAUDE.md) |
| UniFFI — VC Core | `wrappers/uniffi/src/vc/core/` | [context](../wrappers/uniffi/src/vc/core/CLAUDE.md) |
| UniFFI — OID4VCI | `wrappers/uniffi/src/vc/oid4vci/` | [context](../wrappers/uniffi/src/vc/oid4vci/CLAUDE.md) |
| UniFFI — OID4VP | `wrappers/uniffi/src/vc/oid4vp/` | [context](../wrappers/uniffi/src/vc/oid4vp/CLAUDE.md) |
| WASM wrapper root | `wrappers/wasm/src/` | [context](../wrappers/wasm/src/CLAUDE.md) |
| WASM — DID | `wrappers/wasm/src/did/` | [context](../wrappers/wasm/src/did/CLAUDE.md) |
| WASM — In-memory | `wrappers/wasm/src/inmem/` | [context](../wrappers/wasm/src/inmem/CLAUDE.md) |
| WASM — VC | `wrappers/wasm/src/vc/` | [context](../wrappers/wasm/src/vc/CLAUDE.md) |
| WASM — VC Core | `wrappers/wasm/src/vc/core/` | [context](../wrappers/wasm/src/vc/core/CLAUDE.md) |
| WASM — OID4VCI | `wrappers/wasm/src/vc/oid4vci/` | [context](../wrappers/wasm/src/vc/oid4vci/CLAUDE.md) |
| WASM — OID4VP | `wrappers/wasm/src/vc/oid4vp/` | [context](../wrappers/wasm/src/vc/oid4vp/CLAUDE.md) |
| Askar plugin — Node.js | `plugins/askar/wrappers/nodejs/src/` | [context](../plugins/askar/wrappers/nodejs/src/CLAUDE.md) |

## Cross-domain relationships
- Depends on: all of `src/` (the core SDK), `one-core-asdk`
- Used by: downstream consumers — Node.js applications, Android/iOS apps (via UniFFI), browser/WASM apps

## Key decisions / constraints
- **Node.js** uses NAPI-RS (`#[napi]` macros); async methods become JS Promises via `napi::bindgen_prelude::AsyncTask`.
- **UniFFI** uses `#[uniffi::export]`; targets Kotlin (Android) and Swift (iOS); foreign trait implementations use the `with_foreign` pattern; `JsonValue` is a custom_type bridging `serde_json::Value` to a JSON string.
- **WASM** uses `wasm-bindgen` (`#[wasm_bindgen]`); async methods use `wasm_bindgen_futures::future_to_promise`; all types must be `!Send` compatible (`?Send` on async traits).
- The WASM wrapper does **not** expose DIDComm — that module is non-wasm only.
- Each wrapper provides its own `HttpClient` implementation (Node.js: callback-based; UniFFI: `with_foreign`; WASM: `ReqwestHttpClient` with wasm-compatible backend).
- **Delegate SD-JWT (gated `delegate-sd-jwt`, off by default):** delegation is handled inside the existing `Holder::present_credentials(_auto)` (no new Holder method); the feature adds only `Verifier::verify_and_extract_presentation` (verify + return raw presentations so a Delegate Holder can store a dSD-JWT grant) to the trait surface. Wrappers hold `Box<dyn Holder>` / `Box<dyn Verifier>` and forward a fixed method set, so they compile unchanged; surfacing `verify_and_extract_presentation` through NAPI/WASM/UniFFI is a follow-up. (The `openid4vp` bump that backs this feature added a `content` field to `TransactionDataItem`; ordinary constructors in the UniFFI wrapper and the verifier demo were updated to set `content: None`.)

