# didcomm::protocol — Context

## Purpose
Root of all DIDComm protocol implementations. Each sub-module is a self-contained protocol that implements `Protocol` (and usually one or more `MessageHandler`s).

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; declares and re-exports sub-modules |
| `aries/` | Aries-compatible protocols (issuance, present-proof, problem-report, empty) — see [aries/CLAUDE.md](aries/CLAUDE.md) |
| `basic_message/` | DIDComm Basic Message 2.0 — see [basic_message/CLAUDE.md](basic_message/CLAUDE.md) |
| `outofband/` | Out-of-Band 2.0 invitation creation and acceptance — see [outofband/CLAUDE.md](outofband/CLAUDE.md) |
| `tictactoe/` | Example/demo protocol (not for production use) — see [tictactoe/CLAUDE.md](tictactoe/CLAUDE.md) |

## Registration flow
```rust
let protocol = MyProtocol::new(&agent, storage, ...);
agent.register_protocol(protocol).await?;
```
`ProtocolRegistry` stores `Box<dyn Protocol>` and extracts all handlers on registration. Dispatch is purely by message type string match.

## Conventions across all protocol modules
- Constants `PROTOCOL_NAME` and `PROTOCOL_VERSION` are defined at module level.
- Message type constants match the final segment of the DIDComm type URI.
- Each protocol exposes its own `Error` enum and `Result<T>` alias.
- Protocols hold a clone of `Agent` so they can call `agent.send_message`.
- `EventEmitter<K, V>` is embedded in stateful protocols; consumers call `.observe(key)` to get a `(Subscription, EventObservable<V>)` pair.

## Dependencies
- Depends on: `crate::didcomm::core::{Protocol, MessageHandler, ProtocolRegistry}`, `crate::didcomm::agent::Agent`
- Used by: `crate::didcomm::agent` (registers protocols), application entry points

## Constraints
- Non-wasm only.
