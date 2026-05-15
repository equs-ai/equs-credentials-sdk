# didethr — Context

## Purpose
Implements the `did:ethr` DID method resolver for ASDK. It reads the EtherDIDRegistry smart contract on any EVM-compatible chain via JSON-RPC, replays the on-chain event history (`DIDOwnerChanged`, `DIDDelegateChanged`, `DIDAttributeChanged`) to reconstruct a W3C DID document, and exposes the result through the `DIDResolver` trait so it can be registered with `UniversalResolver`.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; declares and re-exports `client`, `registry`, `types`, and `utils` sub-modules. |
| `client.rs` | `DIDEthr` — the public resolver struct; implements `DIDResolver` + `DIDMethod`; owns a list of `EthrDidRegistry` instances; routes DIDs to the correct registry by chain ID or named alias; drives event-history replay to produce a `DidRecord`. |
| `registry.rs` | `EthrDidRegistry` — JSON-RPC client for a single EVM chain; calls `eth_call` (changed selector), `eth_getLogs`, and `eth_getBlockByNumber`; decodes ABI-encoded log data into typed `DidEvents`. Also exposes `EthrDidEventTopics` for configurable Keccak256 topic hashes. |
| `utils.rs` | Stateless helpers: `format_bytes32_string`, `parse_bytes32_string` (bytes32 ↔ UTF-8), and `is_unique` (iterator deduplication check). |
| `types/` | All domain types (addresses, blocks, events, builder, resolution structs) — see [types/CLAUDE.md](types/CLAUDE.md). |

## Key types / traits
- `DIDEthr` — implements `DIDResolver`; the entry point for `did:ethr` resolution; supports multiple chains simultaneously.
- `EthrDidRegistry` — per-chain JSON-RPC client; issues `eth_call` and `eth_getLogs` requests; decodes raw ABI log data into `DidEvents`.
- `EthrDidEventTopics` — holds the three configurable Keccak256 topic hashes used to filter EtherDIDRegistry logs.

## Dependencies
- Depends on: `crate::did::universal::DIDResolver` (trait), `crate::did::{ResolutionError, ResolutionOutput}`, `crate::http::HttpClient` (for `EthrDidRegistry`), `ssi` crate (`DIDMethod`, `Document`), `async_trait`, `serde_json`, `hex`
- Used by: callers that register `DIDEthr` with `UniversalResolver` (Node.js wrapper, Swift/Kotlin UniFFI wrappers, integration tests)

## Constraints
- Non-wasm only: `DIDEthr` and `EthrDidRegistry` perform async HTTP I/O; the parent `did` module gates this sub-module with `#[cfg(not(target_arch = "wasm32"))]`.
