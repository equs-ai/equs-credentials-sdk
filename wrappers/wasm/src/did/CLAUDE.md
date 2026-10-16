# did — Context

## Purpose
Exposes DID method utilities and a universal DID resolver to JavaScript/TypeScript via wasm-bindgen. Provides `#[wasm_bindgen]` structs for `DIDKey`, `DIDWeb`, and `UniversalDIDResolver`, plus a `JsDIDResolver` adapter that bridges a JS-supplied `DIDResolver` callback into the SDK's internal async `DIDResolver` trait. All types are single-threaded (`?Send`) to satisfy the WASM constraint.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared DID types: `VerificationMethodKey` wasm_bindgen struct pairing a `JsKeyHandle` with verification relationship types. Declares opaque extern JS types: `DIDResolution`, `DIDVerificationMethod`, `ResolutionOptions`. Provides `TryFrom<DIDResolution> for ResolutionOutput` (and reverse) for converting between JS-side opaque objects and Rust SDK types. |
| `resolver.rs` | `JsDIDResolver` — wraps an opaque JS `DIDResolver` object and implements the SDK's `DIDResolver` async trait (`?Send`) by forwarding `resolve_representation` calls to the JS side via `wasm_bindgen_futures`. |
| `universal_resolver.rs` | `UniversalDIDResolver` — wasm_bindgen struct wrapping `equs_sdk::did::UniversalResolver`. Exposes `addResolver`, `resolveVerificationMethod`, and `resolve` as wasm-bound async methods. |
| `key.rs` | `DIDKey` — wasm_bindgen struct. Exposes `generate(key: JsKeyHandle) -> Result<String>` for producing a `did:key` DID from a key handle. |
| `web.rs` | `DIDWeb` — wasm_bindgen struct. Exposes `generateDidFromUrl` and `generateDidDocument` for the `did:web` method. |

## Key types / traits
- `UniversalDIDResolver` — WASM class for full DID resolution; supports adding custom resolvers via `addResolver`.
- `JsDIDResolver` — Rust adapter bridging a JS `DIDResolver` callback into the SDK's internal `DIDResolver` async trait (`?Send`).
- `VerificationMethodKey` — WASM struct pairing a key handle with a set of verification relationship types.
- `DIDKey`, `DIDWeb` — WASM classes for DID generation.

## Dependencies
- Depends on: `equs_sdk::did` (including `didkey`, `didweb`, `universal`), `crate::kms::JsKeyHandle`, `crate::http`
- Used by: `crate::vc::oid4vci::builder`, `crate::vc::oid4vp::builder`, WASM consumer TypeScript code

## Constraints
- All async impls use `#[async_trait(?Send)]` — no `Arc`, `Mutex`, or thread-safety required.
- JS-side opaque types are declared via `extern "C"` blocks; their fields are accessed only through getter methods.
