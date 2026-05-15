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

