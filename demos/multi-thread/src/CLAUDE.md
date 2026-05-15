# multi-thread/src — Context

## Purpose
Runnable demo binary that stress-tests the OID4VCI issuance flow under concurrent load. Spins up an `actix-web` HTTP server acting as an issuer and issues SD-JWT credentials to multiple holder clients in parallel across 20 Tokio worker threads.

## Files

| File | Role |
|------|------|
| `main.rs` | Entry point: configures `LocalKms`, `InMemVault`, `ReqwestClient`, and `Issuer`; starts the actix server; spawns N concurrent holder tasks that each perform a full OID4VCI pre-authorized-code flow. |

## Key types / traits
- Uses `vc::oid4vci::{Issuer, Holder}` directly from `agent_sdk`.
- `AppState` — shared actix state holding the boxed `Issuer` instance.
- Default concurrency: 100 runs (`DEFAULT_RUNS`), configurable via CLI args.

## Dependencies
- Depends on: `agent_sdk` (oid4vci, kms, inmem, reqwest), `actix-web`, `tokio` (multi_thread, 20 workers), `rand`
- Used by: developers testing concurrent issuance performance

## Constraints
- Demo / development use only; hard-codes a dummy Bearer token and `localhost:4000`.
