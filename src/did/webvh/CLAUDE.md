# webvh — Context

## Purpose
Implements DID resolution for the `did:webvh` method by wrapping `one-core`'s `DidWebVh` resolver and exposing it through EQUS SDK's `DIDResolver` trait.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports `client`. |
| `client.rs` | `DIDWebVh` resolver struct, `OneCoreHttpClientAdapter` bridging EQUS SDK's `HttpClient` to `one-core`'s incompatible interface, and unit tests with JSONL DID log fixtures. |

## Key types / traits
- `DIDWebVh` — public resolver struct; implements `DIDResolver` and wraps `one-core::DidWebVh`.
- `OneCoreHttpClientAdapter` — private adapter converting EQUS SDK `HttpClient::async_call` calls into `one-core::HttpClient::send` calls.
- `NoopKeyProvider` — no-op `KeyProvider` used because resolution never requires key storage.

## Dependencies
- Depends on: `crate::did::universal` (`DIDResolver` trait), `crate::http` (`HttpClient`), `one-core` (did method + http client interfaces)
- Used by: consumers that register `DIDWebVh` with `UniversalResolver::add_resolver`

## Constraints
- Non-wasm only — the entire `webvh` module is excluded on `wasm32` targets.
