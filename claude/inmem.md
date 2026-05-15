# In-memory — Summary

## What this domain does
Provides complete in-memory implementations of every ASDK persistence and key-management interface. Its purpose is twofold: enable tests to run without external dependencies, and let quick-start applications or CI environments operate without a real KMS or database. Every concrete type here implements a trait defined in the core domain.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| KMS, vault, storage, nonce implementations | `src/inmem/` | [context](../src/inmem/CLAUDE.md) |
| Cryptographic key implementations | `src/inmem/crypto/` | [context](../src/inmem/crypto/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `crate::crypto`, `crate::kms`, `crate::storage`, `crate::vault`, `crate::nonce`, `crate::vc` (for `Credential` type in `InMemVault`), `askar-crypto`, `bip32`, `ed25519-dalek`
- Used by: tests throughout the entire crate; `wrappers/nodejs`, `wrappers/wasm`, `wrappers/uniffi` (all expose `InMemKms` and `InMemVault` for SDK consumers who opt in)

## Key decisions / constraints
- The entire `src/inmem/` module is gated by `#[cfg(any(test, feature = "in-memory"))]` — never compiled into production builds unless the feature is explicitly enabled.
- `LocalKms` is the canonical test KMS used in all unit and E2E tests; use it instead of mocking `Kms`.
- `InMemStorage<K, V>` is generic and backs both `LocalKms` (key storage) and `LocalNonceHandler` (nonce storage).
- `IndexStorage` provides a secondary tag-based index shared by `LocalKms` and `InMemVault` for filtered lookups.
- Supported key types: Ed25519, P256, K256, Bls12381, BIP32-derived keys.

