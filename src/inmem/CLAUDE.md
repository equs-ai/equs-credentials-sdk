# inmem — Context

## Purpose
Provides complete in-memory implementations of every Equs SDK persistence and key-management interface, enabling tests and quick-start applications without external dependencies.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports sub-modules. |
| `kms.rs` | `LocalKms` — in-memory `Kms` + `DerivativeKms` (BIP32, ECDH-1PU, ECDH-ES); `KeyHandle` enum dispatching over all supported key types. |
| `storage.rs` | `InMemStorage<K, V>` — generic `HashMap`-backed `Storage` implementation with transaction support. |
| `vault.rs` | `InMemVault` — `Vault` implementation for storing, retrieving, and searching `Credential`s. |
| `index_storage.rs` | `IndexStorage` — secondary index mapping field tags to primary storage IDs (shared by `LocalKms` and `InMemVault`). |
| `nonce.rs` | `LocalNonceHandler` — `NonceHandler` backed by `InMemStorage`. |
| `utils.rs` | `intersection` — private helper for computing set intersections across index lookups. |
| `crypto/` | Concrete cryptographic suites (Ed25519, P256, K256, Bls12381, Bip32) — see [crypto/CLAUDE.md](crypto/CLAUDE.md). |

## Key types / traits
- `LocalKms` — implements `Kms<KeyHandle>` and `DerivativeKms<BIP32Params | ECDH1PUParams | ECDHESParams>`.
- `KeyHandle` — enum (`Ed25519 | P256 | K256 | Bls12381`) implementing `crypto::SigningKey + VerifyingKey + Key`.
- `InMemStorage<K, V>` — generic in-memory `Storage`.
- `InMemVault` — in-memory `Vault`.
- `LocalNonceHandler` — in-memory `NonceHandler`.
- `IndexStorage` — shared secondary-index utility.

## Dependencies
- Depends on: `crate::crypto`, `crate::kms`, `crate::storage`, `crate::vault`, `crate::nonce`, `crate::vc`, `askar-crypto`, `bip32`, `ed25519-dalek`
- Used by: tests throughout the crate; applications that opt into the `in-memory` feature

## Constraints
- The entire module is gated by `#[cfg(any(test, feature = "in-memory"))]`.
