# Plugins — Summary

## What this domain does
Provides optional, pluggable extensions to EQUS Credentials SDK's core storage and key-management interfaces. Currently contains a single plugin: `askar`, which implements `Kms` and `Vault` backed by the Hyperledger Aries Askar secure storage library, enabling hardware-backed key storage and encrypted credential persistence on native targets.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| Plugins root | `plugins/` | [context](../plugins/CLAUDE.md) |
| Askar plugin root | `plugins/askar/` | [context](../plugins/askar/CLAUDE.md) |
| Askar Rust source | `plugins/askar/src/` | [context](../plugins/askar/src/CLAUDE.md) |
| Askar — Node.js wrapper | `plugins/askar/wrappers/nodejs/src/` | [context](../plugins/askar/wrappers/nodejs/src/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `crate::kms`, `crate::vault`, `crate::storage` (implements these traits), `askar-crypto`, `aries-askar`
- Used by: production applications that require secure key storage beyond the in-memory implementation; exposed through the Node.js wrapper

## Key decisions / constraints
- Plugins are separate crates (`plugins/askar/Cargo.toml`) — they are never compiled into the core SDK library; consumers must explicitly depend on them.
- The Askar plugin is **native-only** — it links against native Askar libraries and is not available on wasm targets.
- The Node.js wrapper for Askar follows the same NAPI-RS pattern as `wrappers/nodejs/`.
- Profile provisioning is idempotent on both the Rust and Node.js surfaces (`AskarStorage::ensure_profile`, formerly `create_profile`) — an existing profile is success, not a `Duplicate` error.

