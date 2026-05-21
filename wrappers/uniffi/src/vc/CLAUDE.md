# vc — Context

## Purpose
Top-level VC module for the UniFFI wrapper. Defines shared credential type mappings via UniFFI `custom_type!` and remote record macros, then re-exports the protocol-agnostic core API (`core_api/`) and the OID4VCI / OID4VP sub-areas. Acts as the central hub for credential-format type bridging between the SDK's internal types and the UniFFI type system consumed by Kotlin/Swift.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| `mod.rs` | Declares `pub mod core_api`, `pub mod oid4vci`, `pub mod oid4vp`. Defines UniFFI remote types: `Alg` enum, `VCFormat` enum, `CredentialMetadata` record. Defines `CredentialData` record + `Credential` custom type (bidirectional serialization). Re-exports `VCStatus`, `TslVcStatus` remote enums. |
| `core_api/` | Protocol-agnostic core API surface. Currently holds `signer.rs` — `VCCoreCredentialSigner` UniFFI object exposing `signCredential(unsigned_credential: String)` over the externally-tagged JSON wire shape (`JsonValue` is bridged as a String at the FFI boundary). Constructed from a foreign-trait `Kms` + `UniversalDIDResolver`; matches the wasm/nodejs `VCCoreCredentialSigner` shape so the same `UnsignedCredential` payload works across all wrappers. |
| `oid4vci/` | OID4VCI issuance protocol bindings — see [oid4vci/CLAUDE.md](oid4vci/CLAUDE.md) |
| `oid4vp/` | OID4VP presentation protocol bindings — see [oid4vp/CLAUDE.md](oid4vp/CLAUDE.md) |

## Key types / traits
- `Credential` custom type — bridged via `CredentialData` record (format + payload string); supports JwtVcJson, JwtVcJsonLd, LdpVc, SdJwt.
- `CredentialMetadata` remote record — carries type, format, kid, optional alg, and fields.
- `Alg` remote enum — `ES256`, `ES256K`, `EdDSA`, `BBS`.
- `VCFormat` remote enum — all five VC formats.
- `VCStatus`/`TslVcStatus` remote enums — status list token statuses.
- `VCCoreCredentialSigner` (in `core_api/signer.rs`) — Stand-alone signer wrapping `CredentialSigner<WrappedKeyHandle, WrappedKms>`; takes externally-tagged `UnsignedCredential` JSON as a `String` (via the `JsonValue` custom_type).

## Dependencies
- Depends on: `agent_sdk::vc`, `agent_sdk::vc::core` (`CredentialSigner`, `SignCredential`, `UnsignedCredential`), `agent_sdk::crypto::Alg`, `uniffi` custom_type/remote macros, `crate::common::JsonValue`, `crate::key_handle::WrappedKeyHandle`, `crate::kms::{Kms, WrappedKms}`, `crate::did::UniversalDIDResolver`
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vault` (CredentialEntry uses Credential type)
