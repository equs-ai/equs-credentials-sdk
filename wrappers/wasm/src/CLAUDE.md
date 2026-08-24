# wasm/src — Context

## Purpose
Root of the wasm-bindgen browser/WASM wrapper crate. Declares all top-level modules that together expose the Equs SDK library to JavaScript/TypeScript consumers running in a browser or Node.js WASM environment. Top-level files handle cross-cutting concerns: opaque JS crypto types, HTTP client bridging (JS callbacks and `ReqwestHttpClient`), key-handle and KMS JS interface adapters, nonce handling, vault access, and utility functions for JS/Rust value conversion. Sub-areas `did/`, `inmem/`, and `vc/` are documented in their own context files.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| `lib.rs` | Crate root. Declares all modules (`crypto`, `did`, `http`, `inmem`, `kms`, `nonce`, `utils`, `vault`, `vc`). Optional `wee_alloc` global allocator for reduced binary size. |
| `crypto.rs` | Opaque extern JS types: `NonceData`, `KeyMetadata`, `KeyType`, `Alg` — all declared via `#[wasm_bindgen(typescript_type = "...")]`. |
| `http.rs` | `JsHttpRequest` opaque extern type with `url`, `method`, `headers`, `body` getters. `HttpMethod` Rust enum with `TryFrom<String>`. `HttpResponse` wasm_bindgen struct (status code, headers as `JsValue`, optional body). `ReqwestHttpClient` wasm_bindgen struct with `new()` (secure) and `insecure()` constructors; `asyncCall(request)` method returning a `Promise<HttpResponse>`. Internal helpers `parse_js_headers`, `process_headers`, `convert_option_string_to_vec_u8`. |
| `kms.rs` | `KeyHandle` / `Kms` opaque extern JS types declared via `extern "C"`. `JsKeyHandle(Rc<KeyHandle>)` — wraps a JS key handle, implements `Key`, `Signer`, and `Verifier` via `#[async_trait(?Send)]`. `JsKms(Rc<Kms>)` — wraps a JS KMS; implements `Kms` trait. `test-utils` feature gate exports `KeyHandleTestHelper` and `KmsTestHelper` for TypeScript tests. |
| `nonce.rs` | `NonceHandler` opaque extern JS type with `generate` and `validate` async method declarations. `JsNonceHandler` — wraps a JS `NonceHandler` and implements `equs_sdk::nonce::NonceHandler` via `#[async_trait(?Send)]`. |
| `utils.rs` | `Claims` opaque extern JS type. `resolveMetadata` and `parseClaims` wasm-exported async functions. `set_panic_hook` (enables `console_error_panic_hook` when feature is active). `js_value_to_string`, `get_property` helpers. `convert_to_rust_object<T, R>` (serde_wasm_bindgen deserialize), `convert_to_opaque_object<T, R>` (json_compatible serialize + `dyn_into`), `convert_to_opaque_object_unchecked<T, R>` (json_compatible serialize + `unchecked_into`). |
| `vault.rs` | `Vault` opaque extern JS type with `storeCredential`, `deleteCredential`, `getCredential`, `getCredentials`, `findCredentials` method declarations. `JsVault` — wraps a JS `Vault` and implements `equs_sdk::vault::Vault` via `#[async_trait(?Send)]`. `test-utils` feature gate exports `VaultTestHelper`. |
| `did/` | DID method utilities and `UniversalDIDResolver` — see [did/CLAUDE.md](did/CLAUDE.md) |
| `inmem/` | In-memory KMS and vault concrete implementations — see [inmem/CLAUDE.md](inmem/CLAUDE.md) |
| `vc/` | VC type bridging, OID4VCI, and OID4VP sub-areas — see [vc/CLAUDE.md](vc/CLAUDE.md) |

## Key types / traits
- `JsKeyHandle` / `JsKms` — Rust-side wrappers implementing SDK `Key`/`Signer`/`Verifier`/`Kms` traits against JS-supplied opaque objects.
- `JsVault` — Rust-side bridge implementing SDK `Vault` trait against a JS-supplied `Vault` object.
- `JsNonceHandler` — Rust-side bridge implementing SDK `NonceHandler` trait against a JS-supplied `NonceHandler` object.
- `ReqwestHttpClient` — Concrete HTTP client backed by `reqwest`; provided as a default for callers that do not supply a custom JS HTTP client.
- `convert_to_opaque_object_unchecked` — Primary serialization helper; used throughout to serialize Rust structs into TypeScript-typed opaque JS values.

## Dependencies
- Depends on: `equs_sdk` (all core modules), `wasm_bindgen`, `wasm_bindgen_futures`, `js_sys`, `web_sys`, `serde_wasm_bindgen`, `async_trait`, `serde_json`
- Used by: TypeScript/JavaScript browser and Node.js WASM consumers

## Constraints
- All async trait implementations use `#[async_trait(?Send)]` — the entire crate is single-threaded.
- Uses `Rc` (not `Arc`) for shared ownership inside `JsKeyHandle` and `JsKms`.
- Optional `wee_alloc` global allocator reduces WASM binary size when the `wee_alloc` feature is enabled.
- `test-utils` feature exposes additional wasm_bindgen helpers (`KeyHandleTestHelper`, `KmsTestHelper`, `VaultTestHelper`) only for test builds.
