# did — Context

## Purpose
Exposes DID method utilities and a universal DID resolver to Kotlin and Swift via UniFFI. Provides `#[uniffi::export]` objects for `DIDKey`, `DIDWeb`, and `UniversalDIDResolver`, plus a `DIDResolver` foreign-trait interface that allows mobile callers to supply custom resolver implementations.

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines all shared DID types: `DIDResolutionOptions`, `VerificationMethodKey`, `VerificationMethod`, `DIDResolution`, `DIDDocMetadata`, `DIDMetadata`, `VerificationRelationshipType` (re-exported via `#[uniffi::remote]`), and the `DIDResolver` foreign trait + `WrappedDIDResolver` adapter that bridges it to the SDK's internal `DIDResolver` trait. |
| `key.rs` | `DIDKey` — UniFFI object wrapping `ASDKDIDKey`. Exposes `generate(key: WrappedKeyHandle) -> Result<String>`. |
| `web.rs` | `DIDWeb` — UniFFI object wrapping `ASDKDIDWeb`. Exposes `generate_did_from_url` and `generate_did_document`. Takes an `Arc<dyn HttpClient>` at construction. |
| `universal_resolver.rs` | `UniversalDIDResolver` — UniFFI object wrapping `UniversalResolver`. Constructor accepts an optional list of `Arc<dyn DIDResolver>` for custom method support. Exposes `resolve_verification_method` and `resolve`. |

## Key types / traits
- `DIDResolver` — UniFFI foreign trait (`with_foreign`) for custom resolver implementations from Kotlin/Swift.
- `WrappedDIDResolver` — Rust-side adapter converting `Arc<dyn DIDResolver>` to the SDK's internal trait.
- `UniversalDIDResolver` — UniFFI class for full DID resolution.
- `DIDKey`, `DIDWeb` — UniFFI objects for DID generation.
- `VerificationMethodKey` — UniFFI object pairing a `WrappedKeyHandle` with a set of verification relationship types.

## Dependencies
- Depends on: `agent_sdk::did` (including `didkey`, `didweb`, `universal`), `crate::key_handle::WrappedKeyHandle`, `crate::http::HttpClient`
- Used by: `crate::vc::oid4vci::builder`, `crate::vc::oid4vp::builder`, Kotlin/Swift consumer code
