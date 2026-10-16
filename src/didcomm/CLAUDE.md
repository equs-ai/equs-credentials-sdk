# didcomm — Context

## Purpose
Top-level DIDComm V2 module. Provides the full protocol engine for secure, decentralised agent-to-agent messaging: agent lifecycle, connection management, envelope cryptography, protocol dispatch, and transport.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports `agent`, `connection`, `core`, `protocol`, `transport` |
| `agent/` | `Agent<KMS, KH, C>` — top-level runtime facade — see [agent/CLAUDE.md](agent/CLAUDE.md) |
| `connection/` | `ConnectionService` trait + `ConnectionRecord` state machine — see [connection/CLAUDE.md](connection/CLAUDE.md) |
| `core/` | Envelope crypto, dispatcher, message receiver/sender, protocol registry, utilities — see [core/CLAUDE.md](core/CLAUDE.md) |
| `protocol/` | All concrete protocol implementations (Aries, OOB, basic message, tictactoe) — see [protocol/CLAUDE.md](protocol/CLAUDE.md) |
| `transport/` | `InboundTransport` / `OutboundTransport` traits + HTTP impl — see [transport/CLAUDE.md](transport/CLAUDE.md) |

## Architecture

```
                 ┌──────────────┐
Application ──▶  │    Agent     │  ◀── register_protocol / send_message / start / stop
                 └──────┬───────┘
                        │ owns
          ┌─────────────┼──────────────┐
          ▼             ▼              ▼
   ConnectionService  DIDCommService  ProtocolRegistry
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
       MessageReceiver  EnvelopeService  MessageSender
              │                              │
              ▼                              ▼
       DispatcherService            OutboundTransport
              │
              ▼
       ProtocolRegistry ──▶ MessageHandler::handle
```

## Key design decisions
- `Agent` is the single public facade; all DIDComm interaction goes through it.
- Protocols are registered at runtime via `ProtocolRegistry`; dispatch is purely message-type string match.
- Envelope cryptography delegates entirely to the `didcomm` crate via adapter types in `core::envelope`.
- No shared async runtime assumption; works with any tokio executor.

## Dependencies
- Depends on: `crate::did::UniversalResolver`, `crate::kms`, `crate::storage`, `crate::http`, `didcomm` crate, `hyper` (HTTP transport)
- Used by: Node.js wrapper (`wrappers/nodejs`), application code; not used by wasm wrapper

## Constraints
- Entire module is non-wasm only (`#[cfg(not(target_arch = "wasm32"))]`).
- `didcomm-http-transport` feature flag required for HTTP transport compilation.
