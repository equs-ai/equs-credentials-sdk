# askar — Context

## Purpose
Hyperledger Askar plugin for EQUS Credentials SDK: provides production-grade, encrypted KMS and credential vault
implementations backed by the `aries_askar` library, with a Node.js NAPI-RS wrapper.

## Files / Sub-areas

| File/Dir              | Role |
|-----------------------|------|
| src/                  | Core Rust library — `AskarStorage`, `AskarKms`, `AskarVault`. See [src/CLAUDE.md](src/CLAUDE.md). |
| wrappers/nodejs/src/  | NAPI-RS bindings exposing storage, KMS, and vault to Node.js. See [wrappers/nodejs/src/CLAUDE.md](wrappers/nodejs/src/CLAUDE.md). |
| wrappers/nodejs/build.rs | NAPI-RS build script for the Node.js native add-on. |

## Key types / traits (if applicable)
- `AskarStorage` — shared storage handle (provisioning, profiles, sessions).
- `AskarKms` — `Kms<AskarKeyHandle>` backed by Askar key management.
- `AskarVault` — `Vault` backed by Askar entry store.
- Node.js counterparts: `AskarStorage`, `AskarKms`, `AskarKeyHandle`, `AskarVault` (NAPI classes).

## Dependencies
- Depends on: `aries_askar`, `equs_sdk` (core SDK crate), `napi`/`napi-derive` (Node.js wrapper only)
- Used by: Node.js SDK wrapper (`wrappers/nodejs/`), demo applications (`demos/nodejs/`)

## Constraints
- Not compatible with WASM targets; Askar's native SQLite/PostgreSQL backends require OS syscalls.
- The Node.js wrapper must be compiled with `cargo` before being loaded via `require()` in JavaScript.
