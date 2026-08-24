# DID — Summary

## What this domain does
Implements all DID (Decentralised Identifier) methods supported by Equs SDK and the `UniversalResolver` that dispatches resolution across them. Given a DID string, this domain resolves it to a W3C DID document and extracts verification methods and JWKs for use by the VC and DIDComm domains.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| DID module root (UniversalResolver, shared types) | `src/did/` | [context](../src/did/CLAUDE.md) |
| `did:ethr` resolver | `src/did/didethr/` | [context](../src/did/didethr/CLAUDE.md) |
| `did:ethr` domain types | `src/did/didethr/types/` | [context](../src/did/didethr/types/CLAUDE.md) |
| `did:webvh` resolver | `src/did/webvh/` | [context](../src/did/webvh/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `crate::crypto` (key traits), `crate::http` (`HttpClient`), `ssi` crate (DID/JWK types), `one-core` (non-wasm, for `did:webvh` and `did:ethr` implementations)
- Used by: `vc` (issuer/holder/verifier need DID resolution), `didcomm` (envelope packing requires DID doc lookup), all three wrappers (Node.js, WASM, UniFFI)

## Key decisions / constraints
- `UniversalResolver` ships with built-in `did:peer` and `did:web` support; additional methods (`did:ethr`, `did:webvh`) are registered at runtime via `add_resolver(impl DIDResolver)`.
- `DIDResolver` trait requires two methods: `resolve_representation(&self, did, options) → Result<...>` and `method_name() → &str`.
- `did:webvh` and `did:ethr` are **non-wasm only** — gated with `#[cfg(not(target_arch = "wasm32"))]` because they perform HTTP I/O using `one-core`'s HTTP client which requires `Send`.
- New DID method resolvers should follow the `didethr/` directory pattern: a `mod.rs` re-exporting submodules and a `client.rs` containing the resolver struct with embedded `#[cfg(test)] mod tests`.
- The `one-core` `HttpClient` trait (`get/post/send` pattern) is incompatible with Equs SDK's (`async_call` pattern); bridging requires an adapter — see `src/did/webvh/client.rs` for the reference pattern.