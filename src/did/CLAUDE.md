# did — Context

## Purpose
Owns all DID method implementations and the universal resolver used throughout ASDK for DID resolution, DID document generation, and verification method lookup.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root: shared error enum, type aliases, `Resolution`, `VerificationRelationshipType`, `VerificationMethodKey`. |
| `universal.rs` | `DIDResolver` trait + `UniversalResolver` dispatching to per-method resolvers; also implements `VerificationMethodResolver` and `JWKResolver`. |
| `didkey.rs` | `DIDKey` — generates `did:key` identifiers from JWK public keys. |
| `didpeer.rs` | `DIDPeer` — generates and resolves `did:peer` (Numalgo4) identifiers. |
| `didweb.rs` | `DIDWeb` — generates `did:web` identifiers and DID documents; resolves by HTTP fetch. |
| `webvh/` | `did:webvh` resolver (non-wasm only) — see [webvh/CLAUDE.md](webvh/CLAUDE.md). |

## Key types / traits
- `DIDResolver` — async trait for per-method resolution; implement to add a new DID method.
- `UniversalResolver` — dispatches to registered resolvers; built-in: `did:peer`, `did:web`.
- `Error` — snafu-based error enum for all DID operations.
- `VerificationRelationshipType` — enum of W3C verification relationship kinds.
- `VerificationMethodKey` — pairs a `Key` with its set of verification relationships.

## Dependencies
- Depends on: `crate::crypto` (key traits), `crate::http` (`HttpClient`), `ssi` crate (DID/JWK types), `did-peer` crate
- Used by: `crate::vc` (issuer/holder/verifier), `crate::didcomm`, wrappers (Node.js, WASM, UniFFI)

## Constraints
- `webvh` sub-module is non-wasm only (`#[cfg(not(target_arch = "wasm32"))]`).
- DID modules that require `HttpClient` are wasm-compatible when an appropriate client is injected.
