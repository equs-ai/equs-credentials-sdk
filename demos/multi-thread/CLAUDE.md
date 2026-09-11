# multi-thread — Context

## Purpose
Demonstrates that the EQUS SDK `Issuer` API is thread-safe and can handle concurrent credential
requests from multiple holders simultaneously using Actix-web and Tokio.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| src/main.rs | Entry point; dispatches to either `issuer` (starts Actix-web server) or `holders <N>` (spawns N concurrent holder tasks) sub-commands. |
| README.md   | Usage instructions and expected output description. |
| Cargo.toml  | Crate manifest. |

## Dependencies
- Depends on: `equs_sdk` (vc::core), `actix-web`, `tokio`, `reqwest`
- Used by: developers verifying thread-safety of EQUS SDK's issuer under load

## Constraints
- Authorization, session management, and nonce generation are intentionally stubbed out for simplicity.
