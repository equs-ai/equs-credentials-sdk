# vc — Context

## Purpose
Top-level VC module for the Node.js wrapper. Declares the `JsonObject` type alias used throughout the wrapper and re-exports the four VC sub-areas: `core` (protocol-agnostic issuer/holder/verifier), `oid4vci` (issuance protocol), `oid4vp` (presentation protocol), and `status_formats` (status list format types).

## Files

| File | Role |
|------|------|
| `mod.rs` | Declares `pub mod core`, `pub mod oid4vci`, `pub mod oid4vp`, `pub mod status_formats`; defines `pub type JsonObject = serde_json::Map<String, serde_json::Value>` used as the universal JSON interchange type across the Node.js wrapper. |
| `core/` | Protocol-agnostic VC issuer, holder, verifier, and status issuer — see [core/CLAUDE.md](core/CLAUDE.md) |
| `oid4vci/` | OID4VCI issuance protocol bindings — see [oid4vci/CLAUDE.md](oid4vci/CLAUDE.md) |
| `oid4vp/` | OID4VP presentation protocol bindings — see [oid4vp/CLAUDE.md](oid4vp/CLAUDE.md) |
| `status_formats/` | Status list format types — see [status_formats/CLAUDE.md](status_formats/CLAUDE.md) |

## Key types / traits
- `JsonObject` — `serde_json::Map<String, serde_json::Value>`; the canonical opaque JSON object type passed between Rust and TypeScript across all VC and DID APIs.

## Dependencies
- Depends on: `serde_json`, all sub-modules listed above
- Used by: nearly every other module in `wrappers/nodejs/src/` that exchanges structured data with Node.js
