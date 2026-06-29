# VC — Summary

## What this domain does
Implements the full Verifiable Credentials stack: credential issuance, presentation, and verification at the core level; the OID4VCI and OID4VP protocol layers for standards-compliant flows; credential format serialisation (SD-JWT, W3C JSON-LD); and supporting subsystems for metadata, status, proof-of-possession, DCQL, and presentation exchange. This is the largest domain in the SDK.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| Core traits (Issuer, Holder, Verifier) | `src/vc/core/` | [context](../src/vc/core/CLAUDE.md) |
| OID4VCI protocol layer | `src/vc/oid4vci/` | [context](../src/vc/oid4vci/CLAUDE.md) |
| OID4VP protocol layer | `src/vc/oid4vp/` | [context](../src/vc/oid4vp/CLAUDE.md) |
| Credential formats (SD-JWT, JSON-LD) | `src/vc/formats/` | [context](../src/vc/formats/CLAUDE.md) |
| Credential metadata | `src/vc/metadata/` | [context](../src/vc/metadata/CLAUDE.md) |
| Status formats (StatusList2021, etc.) | `src/vc/status_formats/` | [context](../src/vc/status_formats/CLAUDE.md) |
| Proof of Possession | `src/vc/pop/` | [context](../src/vc/pop/CLAUDE.md) |
| DCQL query language | `src/vc/dcql/` | [context](../src/vc/dcql/CLAUDE.md) |
| Presentation Exchange | `src/vc/presentation_exchange/` | [context](../src/vc/presentation_exchange/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `crate::crypto`, `crate::kms`, `crate::http` (`HttpClient`), `crate::did` (`UniversalResolver`), `crate::storage`, `crate::vault`, `one-core-asdk` (JWE/SD-JWT crypto)
- Used by: `didcomm` (WACI/Aries issuance and present-proof protocols embed VC core), all three wrappers (Node.js, WASM, UniFFI expose OID4VCI + OID4VP), `tests/e2e/`

## Key decisions / constraints
- OID4VCI uses a dual-error split: `ProtocolError` (4xx — returned to the client) vs `InternalError` (5xx — server-side fault).
- OID4VP JWE encryption for `direct_post.jwt` response mode is handled via `one-core-asdk`; the optional `JweDecrypt` KMS capability must be present on the verifier's KMS.
- `mso_mdoc` format support is gated and excluded on wasm targets.
- `Credential` and `Claims` implement `ZeroizeOnDrop` to scrub sensitive data from memory.
- DCQL and Presentation Exchange are both supported query formats; the verifier decides which to use per request.
- **Delegate SD-JWT — §7.1 "delegation using presentation", gated `delegate-sd-jwt` (off by default, EXPERIMENTAL — tracks an unstable IETF draft).** A `delegate` `transaction_data` item turns an OID4VP presentation into a delegation grant, handled **transparently in the normal present/verify flow** — no bespoke methods, no client-side branching.
    - **Holder (grant):** `present_credentials(_auto)` produce a **dSD-JWT** for any credential whose presentation input is targeted by a `delegate` item — the decision lives per-credential in `create_presentation_by_input` (no `grant_delegation` method), via core `create_delegated_presentation` → `formats::dsd_jwt::SdJwtAPI::create_delegated_credential` (thin wrappers over `sd_jwt_rs`). Because the choice is per-credential, mixed `transaction_data` (delegate + ordinary) and multi-credential delegation are supported.
    - **Holder binding:** the grant **is** a Holder-bound presentation — the Holder signs the KB-SD-JWT (proof of possession, verified by the chain walk against the issuer/preceding `cnf`). The request `aud`/`nonce` (from the `HolderBinder`) are written into the delegate payload; for a plain dSD-JWT (no trailing KB-JWT) the final KB-SD-JWT link is the key binding, and `sd_jwt_rs` (rev `f775f5f`+) verifies `aud`/`nonce` from that link's Delegate Payload. The wire constants live in `oid4vp/delegate.rs`.
    - **Verifier (accept/verify):** `oid4vp::Verifier::verify_and_extract_presentation` runs the **normal** verification (transaction-data hashes, per-presentation holder binding/PoP) and additionally returns the raw presentations per credential id, so a Delegate Holder can **store** the returned dSD-JWT grant. `verify_presentation` is a thin wrapper returning just the claims. There is no `accept_delegation_grant` and no verifier-side delegate special-casing — a dSD-JWT verifies through the same path as any presentation.
    - With the feature **off**, a `delegate` item is rejected as an unrecognized type (OID4VP §5.1 conformance), not hashed-and-ignored.

