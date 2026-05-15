# vc — Context

## Purpose
Top-level VC module for the WASM wrapper. Declares shared credential type mappings between the SDK's internal types and the wasm-bindgen type system consumed by TypeScript. Defines the Rust-side `JsCredential` / `JsCredentialEntry` structs used for format-aware bidirectional conversion, along with `CredentialsFindResult` and `JsFindVCsFailReason` helpers. Declares opaque extern JS types (`Credential`, `CredentialEntry`, `CredentialMetadata`, `VaultPagination`, etc.) and re-exports the `oid4vci` and `oid4vp` sub-modules.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| `mod.rs` | Declares `pub mod oid4vci` and `pub mod oid4vp`. Declares opaque extern JS types: `Credential`, `CredentialEntry`, `CredentialMetadata`, `VaultPagination`, `JsCredentialsFindResult`, `CredentialExtraVerification`. Defines `JsCredential` (format + payload string) with bidirectional `TryFrom` conversions supporting JwtVcJson, JwtVcJsonLd, LdpVc, SdJwtVc. Defines `JsCredentialEntry` (credential + kid + id). Defines `CredentialsFindResult` and `JsFindVCsFailReason` / `JsFindVCsFailReasonType` for credential search results. |
| `oid4vci/` | OID4VCI issuance protocol bindings — see [oid4vci/CLAUDE.md](oid4vci/CLAUDE.md) |
| `oid4vp/` | OID4VP presentation protocol bindings — see [oid4vp/CLAUDE.md](oid4vp/CLAUDE.md) |

## Key types / traits
- `JsCredential` — Rust serde struct (format + payload) used as the serialization intermediary between the SDK's `Credential` enum and the TypeScript-side opaque `Credential` object.
- `JsCredentialEntry` — Rust serde struct (credential + kid + id); bidirectional `TryFrom` with the SDK's `vault::CredentialEntry`.
- `CredentialsFindResult` — Rust serde struct wrapping either a list of `JsCredentialEntry` items or a `JsFindVCsFailReason`, serialized as a JSON `data` field.
- `Credential` / `CredentialEntry` / `CredentialMetadata` — opaque extern JS types declared via `#[wasm_bindgen(typescript_type = "...")]`.

## Dependencies
- Depends on: `agent_sdk::vc`, `agent_sdk::vault`, `serde_json`, `wasm_bindgen`
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vault` (vault bridge uses `JsCredentialEntry`)
