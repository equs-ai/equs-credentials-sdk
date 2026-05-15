# askar/src — Context

## Purpose
Core Rust library implementing Hyperledger Askar-backed KMS and vault for ASDK, providing
durable, encrypted key and credential storage as an alternative to the in-memory implementations.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| lib.rs   | `AskarStorage` — wraps `aries_askar::Store` with profile-aware session/transaction management, scan support, provisioning, and profile lifecycle. Also defines `AskarStorageConfig`, `KeyMethod`, and the `AskarStorageScan` / `AskarStorageScanParams` scan API. |
| kms.rs   | `AskarKms` (implements `Kms<AskarKeyHandle>`) and `AskarKeyHandle` (implements `Key`, `Signer`, `Verifier`, `KeyHandle`, `AsdkJweDecrypt`). Supports Ed25519, P-256, and K-256 key types; stores public-key tags (SHA-256) for `get_by_public_key` lookup. Unit tests cover all three key types, JWK export, and JWE encrypt/decrypt. |
| vault.rs | `AskarVault` (implements `Vault`) stores credentials as Askar entries keyed by format category; supports `store_credential`, `get_credential`, `get_credentials`, `find_credentials` (tag-filter disjunction), `delete_credential`, and `count_all`. Unit tests cover CRUD, field-filter behaviour, pagination, multi-vault profile isolation. |

## Key types / traits (if applicable)
- `AskarStorage` — central storage handle; shared by both `AskarKms` and `AskarVault`.
- `AskarKms: Kms<AskarKeyHandle>` — implements `agent_sdk::kms::Kms`.
- `AskarKeyHandle: Key + Signer + Verifier + KeyHandle + AsdkJweDecrypt` — implements `agent_sdk::crypto` traits.
- `AskarVault: Vault` — implements `agent_sdk::vault::Vault`.
- `AskarVaultFetchOptions` — Askar-native pagination/sort parameters extending `VaultFetchOptions`.

## Dependencies
- Depends on: `aries_askar`, `agent_sdk` (crypto, kms, vault, vc), `snafu`, `tracing`, `zeroize`, `base64`, `sha2`, `bip32`, `ecdsa`, `rand`, `uuid`, `async_trait`
- Used by: `plugins/askar/wrappers/nodejs/src/`, and optionally by host applications needing persistent storage

## Constraints
- Non-wasm only (Askar has no WASM support).
- Tests use `sqlite://:memory:` with `DeriveKey` method; production deployments should use a persistent DB URL and `RawKey` or `DeriveKey`.
