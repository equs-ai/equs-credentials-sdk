# inmem — Context

## Purpose
Provides concrete in-memory implementations of the `Kms`, `Vault`, and `KeyHandle` interfaces as UniFFI-exported objects, allowing Android and iOS applications to use a local in-process storage backend without an external dependency. These implementations are also the primary testing and demo backend.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports `keyhandle`, `kms`, and `vault` submodules. |
| `keyhandle.rs` | `InMemKeyHandle` — Rust-only struct (not directly exported via UniFFI) wrapping `ASDKInMemKeyHandle`. Implements `crate::key_handle::KeyHandle` trait, providing `pub_key`, `jwk`, `alg`, `sign`, and `verify`. Used internally by `InMemKms`. |
| `kms.rs` | `InMemKms` — UniFFI object wrapping `LocalKms`. Implements `crate::kms::Kms` trait; exported via `#[uniffi::export]`. Constructor `new()` creates a fresh local KMS. Also implements the SDK `Kms` trait via `WrappedKms`. |
| `vault.rs` | `InMemVault` — UniFFI object wrapping `agent_sdk::inmem::vault::InMemVault`. Implements `crate::vault::Vault` trait; exported via `#[uniffi::export]`. Exposes `store_credential`, `delete_credential`, `get_credential`, `get_credentials`, `find_credentials`. |

## Key types / traits
- `InMemKms` — Concrete `LocalKms`-backed KMS satisfying the UniFFI `Kms` foreign trait interface.
- `InMemKeyHandle` — Adapter between the SDK's in-memory key handle and the UniFFI `KeyHandle` trait.
- `InMemVault` — In-memory credential store satisfying the UniFFI `Vault` foreign trait interface.

## Dependencies
- Depends on: `agent_sdk::inmem` (`LocalKms`, `InMemVault`, `KeyHandle`), `crate::key_handle`, `crate::kms`, `crate::vault`, `crate::vc` (for `Alg`)
- Used by: Android demos (`demos/android/`), iOS demos (`demos/ios/`), Kotlin/Swift test code
