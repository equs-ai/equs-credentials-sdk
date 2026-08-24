# tests — Context

## Purpose
Contains the complete integration and end-to-end test suite for Equs SDK, organized into shared
utilities and scenario-specific e2e test modules covering all major supported protocols.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| mod.rs   | Root test crate module; declares `utils` and `e2e` sub-modules. |
| `utils/` | Shared test infrastructure: HTTP emulator, stub DID resolver, static fixtures, and protocol-participant builder helpers — see [utils/CLAUDE.md](utils/CLAUDE.md). |
| `e2e/`   | End-to-end tests for all major Equs SDK flows (vc_core, vc_oid4vci, vc_oid4vp, waci_aries, protocol_engine, custom_did_resolvers) — see [e2e/CLAUDE.md](e2e/CLAUDE.md). |

## Key types / traits (if applicable)
- No public types; this crate is test-only.

## Dependencies
- Depends on: `equs_sdk` (all features), `rstest`, `mockito`, `serde_json`, `oauth2`, `ssi`, `url`, `time`, `uuid`, `futures`
- Used by: CI via `cargo test --features in-memory,didcomm-http-transport`

## Constraints
- Must be compiled and run with `--features in-memory,didcomm-http-transport`.
- E2e DIDComm tests bind to specific loopback ports; avoid running with `--test-threads=1` unless ports are known to be free.
