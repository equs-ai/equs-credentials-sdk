# DIDComm — Summary

## What this domain does
Implements the DIDComm V2 protocol engine for secure, decentralised agent-to-agent messaging. Covers the full stack: cryptographic envelope packing/unpacking, an `Agent` runtime facade, connection lifecycle management, protocol registration and dispatch, and pluggable inbound/outbound transports. Includes production-ready Aries protocol implementations for credential issuance and presentation.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| Agent runtime | `src/didcomm/agent/` | [context](../src/didcomm/agent/CLAUDE.md) |
| Connection service | `src/didcomm/connection/` | [context](../src/didcomm/connection/CLAUDE.md) |
| Core infrastructure | `src/didcomm/core/` | [context](../src/didcomm/core/CLAUDE.md) |
| Envelope crypto (pack/unpack) | `src/didcomm/core/envelope/` | [context](../src/didcomm/core/envelope/CLAUDE.md) |
| Protocol trait abstractions | `src/didcomm/core/protocol/` | [context](../src/didcomm/core/protocol/CLAUDE.md) |
| Protocol implementations root | `src/didcomm/protocol/` | [context](../src/didcomm/protocol/CLAUDE.md) |
| Aries protocols root | `src/didcomm/protocol/aries/` | [context](../src/didcomm/protocol/aries/CLAUDE.md) |
| Aries common types | `src/didcomm/protocol/aries/common/` | [context](../src/didcomm/protocol/aries/common/CLAUDE.md) |
| Aries empty (ACK) | `src/didcomm/protocol/aries/empty/` | [context](../src/didcomm/protocol/aries/empty/CLAUDE.md) |
| Aries Issue Credential v3 | `src/didcomm/protocol/aries/issuance/` | [context](../src/didcomm/protocol/aries/issuance/CLAUDE.md) |
| Issuance — Issuer role | `src/didcomm/protocol/aries/issuance/issuer/` | [context](../src/didcomm/protocol/aries/issuance/issuer/CLAUDE.md) |
| Issuance — Holder role | `src/didcomm/protocol/aries/issuance/holder/` | [context](../src/didcomm/protocol/aries/issuance/holder/CLAUDE.md) |
| Issuance messages | `src/didcomm/protocol/aries/issuance/message/` | [context](../src/didcomm/protocol/aries/issuance/message/CLAUDE.md) |
| Aries Present Proof v3 | `src/didcomm/protocol/aries/present_proof/` | [context](../src/didcomm/protocol/aries/present_proof/CLAUDE.md) |
| Present Proof — Verifier role | `src/didcomm/protocol/aries/present_proof/verifier/` | [context](../src/didcomm/protocol/aries/present_proof/verifier/CLAUDE.md) |
| Present Proof — Holder role | `src/didcomm/protocol/aries/present_proof/holder/` | [context](../src/didcomm/protocol/aries/present_proof/holder/CLAUDE.md) |
| Present Proof messages | `src/didcomm/protocol/aries/present_proof/message/` | [context](../src/didcomm/protocol/aries/present_proof/message/CLAUDE.md) |
| Problem Report | `src/didcomm/protocol/aries/problem_report/` | [context](../src/didcomm/protocol/aries/problem_report/CLAUDE.md) |
| Basic Message 2.0 | `src/didcomm/protocol/basic_message/` | [context](../src/didcomm/protocol/basic_message/CLAUDE.md) |
| Out-of-Band 2.0 | `src/didcomm/protocol/outofband/` | [context](../src/didcomm/protocol/outofband/CLAUDE.md) |
| TicTacToe (demo protocol) | `src/didcomm/protocol/tictactoe/` | [context](../src/didcomm/protocol/tictactoe/CLAUDE.md) |
| Transport abstractions | `src/didcomm/transport/` | [context](../src/didcomm/transport/CLAUDE.md) |
| HTTP transport | `src/didcomm/transport/http/` | [context](../src/didcomm/transport/http/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `crate::did` (`UniversalResolver` for envelope adapter), `crate::kms` (`DIDCommKms`), `crate::storage`, `crate::vault`, `crate::vc::core` (issuance + present-proof roles), `didcomm` crate (envelope crypto), `hyper` (HTTP server)
- Used by: Node.js wrapper (`wrappers/nodejs`); not exposed in WASM or UniFFI wrappers

## Key decisions / constraints
- The **entire module is non-wasm only** — excluded at the `Cargo.toml` feature level via `#[cfg(not(target_arch = "wasm32"))]`.
- `Agent` is the single public facade; all DIDComm interaction (send, receive, register protocol) goes through it.
- Protocols are registered at runtime and dispatched by message type string match — no compile-time protocol list.
- The `didcomm-http-transport` feature flag must be enabled to compile the HTTP transport.
- `StatefulMessageHandler` + `StateMachine` enforce a strict event-sourced state-transition model; state is always persisted before the handler returns.

