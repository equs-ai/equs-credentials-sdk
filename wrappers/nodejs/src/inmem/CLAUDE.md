# inmem — Context

## Purpose
Provides in-memory implementations of KMS, vault, and nonce handler as concrete NAPI classes for Node.js, allowing tests and demos to work without an external storage backend. These classes implement the same interfaces as the production adapters (`Kms`, `Vault`, `NonceHandler`), making them drop-in substitutes.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports `kms`, `nonce`, and `vault` submodules. |
| `kms.rs` | `InMemKms` — NAPI class wrapping `LocalKms`. Exposes `create`, `get`, `get_by_public_key`, `derive_ecdhes`, `derive_ecdh1pu`, and `derive_bip32`. `InMemKeyHandle` — NAPI class wrapping the inmem key handle, exposing `pub_key`, `alg`, `sign`, and `verify`. |
| `nonce.rs` | `LocalNonceHandler` — NAPI class wrapping `equs_sdk::inmem::nonce::LocalNonceHandler`. Exposes `generate` and `validate` as async NAPI methods. |
| `vault.rs` | `InMemVault` — NAPI class wrapping `equs_sdk::inmem::vault::InMemVault`. Exposes `store_credential`, `delete_credential`, `get_credential`, `get_credentials`, and `find_credentials`. |

## Key types / traits
- `InMemKms` — Concrete `LocalKms`-backed KMS for Node.js; also implements ECDH and BIP32 derivation.
- `InMemKeyHandle` — Concrete key handle returned by `InMemKms`.
- `LocalNonceHandler` — Stateful in-memory nonce generator and validator.
- `InMemVault` — In-memory credential store.

## Dependencies
- Depends on: `equs_sdk::inmem` (`LocalKms`, `InMemVault`, `LocalNonceHandler`), `crate::vault` (for `JsCredentialEntry`, `JsVaultPagination`), `crate::vc::core` (for `JsCredential`, `JsCredentialMetadata`, `JsAlg`)
- Used by: Node.js tests and demos; consumed by `crate::vc::core::holder` and `crate::vc::core::issuer` via the `Kms` and `Vault` traits

## Constraints
- Module is gated behind `#[cfg(any(test, feature = "in-memory"))]` in the core SDK. The Node.js wrapper exposes it unconditionally since it is needed for the public API surface.
