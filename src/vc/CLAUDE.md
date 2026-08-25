# vc — Context

## Purpose
The top-level Verifiable Credentials module. It owns the canonical `Credential` and `Presentation` enums (the format-agnostic wrappers used throughout the SDK), exposes the `Claims` / `Claim` value types, and aggregates all sub-modules that implement VC issuance, presentation, verification, and status management. It also re-exports the most commonly used types so callers can import from a single path.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root: defines `Credential`, `Presentation`, `VCStatusesData`, `VCStatus`, `StatusList`, `CredentialError`, `CredentialMetadata`, and `RequestedPresentation`; re-exports `VCFormat`, `VPFormat`, `HasClaims`, `ClaimFormat`, `TslVcStatus`; declares all sub-modules. |
| `claims.rs` | `Claims` (flat `HashMap<String, Claim>`) and `Claim` (typed value enum: Null, Bool, Int, UInt, Float, String, Array, Object). Implements `TryFrom<Value>`/`TryInto<Value>` and `Drop`-based zeroization of sensitive data. |
| `core/` | Abstract actor traits and service implementations — see [core/CLAUDE.md](core/CLAUDE.md) |
| `formats/` | VC format implementations (SD-JWT, JSON-LD, mso_mdoc) — see [formats/CLAUDE.md](formats/CLAUDE.md) |
| `oid4vci/` | OID4VCI protocol layer (issuance) — see [oid4vci/CLAUDE.md](oid4vci/CLAUDE.md) |
| `oid4vp/` | OID4VP protocol layer (presentation) — see [oid4vp/CLAUDE.md](oid4vp/CLAUDE.md) |
| `dcql/` | Digital Credentials Query Language evaluation — see [dcql/CLAUDE.md](dcql/CLAUDE.md) |
| `metadata/` | Credential metadata resolution after acceptance — see [metadata/CLAUDE.md](metadata/CLAUDE.md) |
| `pop/` | Proof of Possession generation and verification — see [pop/CLAUDE.md](pop/CLAUDE.md) |
| `presentation_exchange/` | DIF Presentation Exchange spec implementation — see [presentation_exchange/CLAUDE.md](presentation_exchange/CLAUDE.md) |
| `status_formats/` | VC revocation status list formats (JWT Token Status List) — see [status_formats/CLAUDE.md](status_formats/CLAUDE.md) |

## Key types / traits
- `Credential` — `SdJwt(sd_jwt_vc::Credential)` | `LdpVc(json_ld_vc::VC)` | `JwtVcJson(String)` | `JwtVcJsonLd(String)`; implements `is_expired()`, `is_valid()`, `HasVCFormat`, `HasClaims<Claims>`.
- `Presentation` — `JwtVp(String)` | `LdpVp(json_ld_vc::VP)` | `SdJwtVp(String)` | `MsoMdoc(...)` (non-wasm); implements `HasVPFormat`, `HasCredential<Credential>`.
- `Claims` / `Claim` — typed credential claim map with zeroize-on-drop; converts to/from `serde_json::Value`.
- `CredentialMetadata` — transport struct (type, format, kid, alg, fields) shared between OID4VCI and vault storage.
- `VCStatus` / `VCStatusesData` / `StatusList` — abstraction layer over concrete status-list representations.
- `VCFormatsAPI` / `VCFormatsJsonLdAPI` / `VCFormatsSdJwtAPI` — re-exported format API types for external consumers.
- `DelegationParams` (`#[cfg(feature = "delegate-sd-jwt")]`) — re-exported from `formats::dsd_jwt` so external consumers (e.g. wrapper crates) can call `Holder::create_delegated_credential`; the `formats` module itself is `pub(crate)`.

## Dependencies
- Depends on: `crate::crypto`, `crate::did::universal`, `crate::http`, `crate::kms`, `crate::vault`, `crate::storage`, `crate::nonce`, `crate::reqwest`, external crates `oid4vci`, `openid4vp`, `ssi`, `sd_jwt_rs`, `one_core_portable`
- Used by: `crate::didcomm` (WACI/Aries issuance protocol), wrapper targets (Node.js NAPI-RS, WASM, Kotlin UniFFI, Swift UniFFI)

## Constraints
- `Presentation::MsoMdoc` and `formats::mso_mdoc` are gated with `#[cfg(not(target_arch = "wasm32"))]`.
- `Claim::Drop` zeroes all claim memory; avoid cloning sensitive claims unnecessarily.
