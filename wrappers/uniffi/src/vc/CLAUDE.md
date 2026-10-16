# vc — Context

## Purpose
Top-level VC module for the UniFFI wrapper. Defines shared credential type mappings via UniFFI `custom_type!` and remote record macros, then re-exports the protocol-agnostic core, OID4VCI, and OID4VP sub-areas. Acts as the central hub for credential-format type bridging between the SDK's internal types and the UniFFI type system consumed by Kotlin/Swift.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| `mod.rs` | Declares `pub mod core`, `pub mod oid4vci`, and `pub mod oid4vp`. (`core/api/` is declared inside `core/mod.rs`) Defines UniFFI remote types: `Alg` enum, `VCFormat` enum, `CredentialMetadata` record. Defines `CredentialData` record + `Credential` custom type (bidirectional serialization). Re-exports `VCStatus`, `TslVcStatus` remote enums. |
| `core/` | Protocol-agnostic issuer / holder / verifier / status issuer bindings, and stand-alone `VCCoreCredentialSigner` — see [core/CLAUDE.md](core/CLAUDE.md) |
| `oid4vci/` | OID4VCI issuance protocol bindings — see [oid4vci/CLAUDE.md](oid4vci/CLAUDE.md) |
| `oid4vp/` | OID4VP presentation protocol bindings — see [oid4vp/CLAUDE.md](oid4vp/CLAUDE.md) |

## Key types / traits
- `Credential` custom type — bridged via `CredentialData` record (format + payload string); supports JwtVcJson, JwtVcJsonLd, LdpVc, SdJwt.
- `CredentialMetadata` remote record — carries type, format, kid, optional alg, and fields.
- `Alg` remote enum — `ES256`, `ES256K`, `EdDSA`, `BBS`.
- `VCFormat` remote enum — all five VC formats.
- `VCStatus`/`TslVcStatus` remote enums — status list token statuses.
- `VCCoreCredentialSigner` (in `core/api/signer.rs`) — Stand-alone signer wrapping `CredentialSigner<WrappedKeyHandle, WrappedKms>`; takes externally-tagged `UnsignedCredential` JSON as a `String` (via the `JsonValue` custom_type).

## Dependencies
- Depends on: `equs_sdk::vc`, `equs_sdk::vc::core` (`CredentialSigner`, `SignCredential`, `UnsignedCredential`), `equs_sdk::crypto::Alg`, `uniffi` custom_type/remote macros, `crate::common::JsonValue`, `crate::key_handle::WrappedKeyHandle`, `crate::kms::{Kms, WrappedKms}`, `crate::did::UniversalDIDResolver`
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vault` (CredentialEntry uses Credential type)
