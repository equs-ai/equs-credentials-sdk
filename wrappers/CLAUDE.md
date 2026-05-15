# wrappers — Context

## Purpose
Contains all language-specific wrapper crates that expose the ASDK Rust library to external consumers. Each wrapper targets a different runtime and uses a dedicated FFI framework. The `types/` directory holds shared TypeScript type definitions used by both the `nodejs` and `wasm` wrappers. The `test/` directory holds shared JavaScript/TypeScript test utilities.

## Sub-areas

| Dir | Target | Framework | Role |
|-----|--------|-----------|------|
| `nodejs/` | Node.js (native addon) | NAPI-RS (`napi`, `napi-derive`) | Compiles to a `.node` native addon. Exposes all ASDK capabilities to Node.js via `#[napi]` macros, `ThreadsafeFunction` for async JS callbacks, and `JsonObject` (`serde_json::Map`) as the universal dynamic-JSON interchange type. Includes DIDComm V2 envelope service support. See `nodejs/src/CLAUDE.md`. |
| `uniffi/` | Kotlin (Android) + Swift (iOS) | UniFFI (`uniffi`, `uniffi-bindgen`) | Compiles to a Rust shared library + generated Kotlin/Swift scaffolding. Exposes ASDK via `#[uniffi::export]`, `#[uniffi::remote]`, `uniffi::custom_type!`, and `with_foreign` foreign-trait interfaces. Uses `JsonValue` (serde ↔ String) as the dynamic-JSON bridge type. See `uniffi/src/CLAUDE.md`. |
| `wasm/` | Browser + Node.js WASM | wasm-bindgen | Compiles to a `.wasm` + glue JS module. Exposes ASDK via `#[wasm_bindgen]` structs and opaque `extern "C"` JS types. Fully single-threaded (`?Send`); uses `Rc` not `Arc`. See `wasm/src/CLAUDE.md`. |
| `types/` | TypeScript (shared) | — | Shared TypeScript type declarations (`.d.ts` / `.ts`) consumed by both `nodejs` and `wasm` wrappers. Organized into `did/`, `didcomm/`, `vc/`, and `js_common/` sub-directories. |
| `test/` | JavaScript/TypeScript | — | Shared test helpers in `js_common/` for use by both `nodejs` and `wasm` test suites. |

## Key design principles across all wrappers
- **Adapter pattern**: Each wrapper defines `Wrapped*` / `Js*` structs (e.g., `WrappedKms`, `JsKms`, `JsVault`) that bridge the host language's callback/object mechanism into the SDK's internal async Rust traits.
- **Foreign traits**: UniFFI uses `with_foreign` to allow Kotlin/Swift to implement `Kms`, `Vault`, `HttpClient`, `KeyHandle`, `NonceHandler`, and `DIDResolver`; nodejs uses `ThreadsafeFunction`; WASM uses opaque `extern "C"` JS object types.
- **HTTP abstraction**: All three wrappers expose a `ReqwestHttpClient` backed by `agent_sdk::reqwest::ReqwestClient` as a default, and accept a caller-supplied HTTP client for customization.
- **Credential interchange**: nodejs uses `JsCredential` (format + payload as `JsonObject`); UniFFI uses `Credential` custom_type (format + payload via `CredentialData`); WASM uses `JsCredential` (format + payload) with bidirectional `TryFrom` conversions.
- **Error handling**: nodejs uses `EncodableError` (JSON-serialized `{code, message}`); UniFFI uses a unified `Error` enum with variant per sub-system; WASM returns `JsError` from all fallible wasm-bound functions.

## Dependencies
- All wrappers depend on the `agent_sdk` crate (workspace root `src/`).
- `nodejs/` and `wasm/` share TypeScript type definitions from `wrappers/types/`.
- `uniffi/` generates Kotlin/Swift bindings independently via `uniffi-bindgen`.
