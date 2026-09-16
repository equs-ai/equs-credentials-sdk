# Demos — Summary

## What this domain does
Self-contained example applications demonstrating how to use EQUS Credentials SDK in realistic scenarios. Each demo wires together the SDK's traits with concrete implementations (in-memory KMS, reqwest HTTP) and a real transport layer (actix-web, mobile bindings) to show an end-to-end flow. Demos are not part of the library build — they are separate binaries used for developer onboarding and integration testing.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| Demos root | `demos/` | [context](../demos/CLAUDE.md) |
| OID4VC flow (issuer + holder + verifier) | `demos/oid4vc/` | [context](../demos/oid4vc/CLAUDE.md) |
| OID4VC shared library | `demos/oid4vc/shared/src/` | [context](../demos/oid4vc/shared/src/CLAUDE.md) |
| OID4VC issuer binary | `demos/oid4vc/issuer/src/` | [context](../demos/oid4vc/issuer/src/CLAUDE.md) |
| OID4VC holder binary | `demos/oid4vc/holder/src/` | [context](../demos/oid4vc/holder/src/CLAUDE.md) |
| OID4VC verifier binary | `demos/oid4vc/verifier/src/` | [context](../demos/oid4vc/verifier/src/CLAUDE.md) |
| Multi-thread stress test | `demos/multi-thread/` | [context](../demos/multi-thread/CLAUDE.md) |
| Multi-thread source | `demos/multi-thread/src/` | [context](../demos/multi-thread/src/CLAUDE.md) |
| Node.js demo | `demos/nodejs/` | [context](../demos/nodejs/CLAUDE.md) |
| WASM demo | `demos/wasm/` | [context](../demos/wasm/CLAUDE.md) |
| Android demo | `demos/android/` | [context](../demos/android/CLAUDE.md) |
| iOS demo | `demos/ios/` | [context](../demos/ios/CLAUDE.md) |
| Keycloak integration demo | `demos/keycloak/` | [context](../demos/keycloak/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `equs_sdk` (the full SDK crate), `actix-web` (Rust demos), NAPI-RS (Node.js demo), wasm-bindgen (WASM demo), UniFFI (mobile demos)
- Used by: developers learning the SDK; CI smoke tests

## Key decisions / constraints
- Demos use hard-coded keys, tokens, and localhost URLs — they are **not production-ready**.
- The OID4VC demo is the canonical full-stack example: run issuer, holder, and verifier as three separate processes.
- The multi-thread demo is specifically for load/concurrency testing of the OID4VCI flow (default 100 concurrent issuances).

