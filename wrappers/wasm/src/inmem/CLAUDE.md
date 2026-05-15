# inmem — Context

## Purpose
Provides concrete in-memory implementations of the `Kms` and `Vault` interfaces as wasm_bindgen-exported structs, allowing browser/WASM applications to use a local in-process storage backend without an external dependency. These implementations are the primary testing and demo backend in the WASM target.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports `kms` and `vault` submodules. |
| `kms.rs` | `InMemKeyHandle(KeyHandle)` — wasm_bindgen struct wrapping the SDK's in-memory key handle opaque JS type; implements the JS `KeyHandle` interface for use within `InMemKms`. `InMemKms(LocalKms)` — wasm_bindgen struct wrapping `LocalKms`; created via `new()` constructor. A `test-utils` feature gate exports `KeyHandleTestHelper` and `KmsTestHelper` for use in TypeScript tests. |
| `vault.rs` | `InMemVault` — wasm_bindgen struct wrapping `agent_sdk::inmem::vault::InMemVault`. Exposes `storeCredential`, `deleteCredential`, `getCredential`, `getCredentials`, and `findCredentials` as wasm-bound async methods. |

## Key types / traits
- `InMemKms` — Concrete `LocalKms`-backed KMS satisfying the WASM `Kms` JS interface.
- `InMemKeyHandle` — Wrapper around the SDK's in-memory key handle that fulfills the WASM `KeyHandle` JS type contract.
- `InMemVault` — In-memory credential store satisfying the WASM `Vault` JS interface.

## Dependencies
- Depends on: `agent_sdk::inmem` (`LocalKms`, `InMemVault`), `crate::kms` (JS opaque `Kms`/`KeyHandle` types), `crate::vc` (for credential/metadata types)
- Used by: WASM browser demos, TypeScript test code, `crate::vc::oid4vci::builder`, `crate::vc::oid4vp::builder`

## Constraints
- All types are single-threaded (`?Send`); uses `Rc` internally, not `Arc`.
- `KeyHandleTestHelper` and `KmsTestHelper` are only compiled when the `test-utils` feature is active.
