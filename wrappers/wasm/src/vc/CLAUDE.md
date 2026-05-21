# vc — Context

## Purpose
Top-level VC module for the WASM wrapper. Declares shared credential type mappings between the SDK's internal types and the wasm-bindgen type system consumed by TypeScript. Defines the Rust-side `JsCredential` / `JsCredentialEntry` structs used for format-aware bidirectional conversion, along with `CredentialsFindResult` and `JsFindVCsFailReason` helpers. Declares opaque extern JS types (`Credential`, `CredentialEntry`, `CredentialMetadata`, `VaultPagination`, etc.) and re-exports the protocol-agnostic core API (`core_api/`) and the `oid4vci` / `oid4vp` sub-modules.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| `mod.rs` | Declares `mod core_api`, `mod oid4vci`, `mod oid4vp`. Declares opaque extern JS types: `Credential`, `CredentialEntry`, `CredentialMetadata`, `VaultPagination`, `JsCredentialsFindResult`, `CredentialExtraVerification`. Defines `JsCredential` (format + payload string) with bidirectional `TryFrom` conversions supporting JwtVcJson, JwtVcJsonLd, LdpVc, SdJwtVc. Defines `JsCredentialEntry` (credential + kid + id). Defines `CredentialsFindResult` and `JsFindVCsFailReason` / `JsFindVCsFailReasonType` for credential search results. |
| `core_api/` | Protocol-agnostic core API surface. Currently holds `signer.rs` — `VCCoreCredentialSigner` wasm-bindgen struct exposing `signCredential(unsigned: js_sys::Object)`. Decodes the JS object via `serde_wasm_bindgen` into the externally-tagged `UnsignedCredential` enum, then delegates to a `CredentialSigner<JsKeyHandle, JsKms>`. Constructed from a JS-supplied `Kms` + `UniversalDIDResolver`; matches the nodejs/uniffi `VCCoreCredentialSigner` shape so the same payload works across wrappers. Single-threaded (`Rc` for shared ownership, `?Send`). |
| `oid4vci/` | OID4VCI issuance protocol bindings — see [oid4vci/CLAUDE.md](oid4vci/CLAUDE.md) |
| `oid4vp/` | OID4VP presentation protocol bindings — see [oid4vp/CLAUDE.md](oid4vp/CLAUDE.md) |

## Key types / traits
- `JsCredential` — Rust serde struct (format + payload) used as the serialization intermediary between the SDK's `Credential` enum and the TypeScript-side opaque `Credential` object.
- `JsCredentialEntry` — Rust serde struct (credential + kid + id); bidirectional `TryFrom` with the SDK's `vault::CredentialEntry`.
- `CredentialsFindResult` — Rust serde struct wrapping either a list of `JsCredentialEntry` items or a `JsFindVCsFailReason`, serialized as a JSON `data` field.
- `Credential` / `CredentialEntry` / `CredentialMetadata` — opaque extern JS types declared via `#[wasm_bindgen(typescript_type = "...")]`.
- `VCCoreCredentialSigner` (in `core_api/signer.rs`) — Stand-alone signer wrapping `CredentialSigner<JsKeyHandle, JsKms>`; accepts the externally-tagged `UnsignedCredential` JS object and returns the opaque `Credential`.

## Dependencies
- Depends on: `agent_sdk::vc`, `agent_sdk::vc::core` (`CredentialSigner`, `SignCredential`, `UnsignedCredential`), `agent_sdk::vault`, `serde_json`, `wasm_bindgen`, `serde_wasm_bindgen`, `crate::kms::{JsKms, Kms}`, `crate::did::universal_resolver::UniversalDIDResolver`, `crate::utils::{convert_to_rust_object, convert_to_opaque_object_unchecked}`
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vault` (vault bridge uses `JsCredentialEntry`)
