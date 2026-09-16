# nodejs/src — Context

## Purpose
NAPI-RS Rust source exposing the Askar plugin's KMS and vault implementations as a native
Node.js add-on (`askar-nodejs`), consumed by the Node.js wrapper layer.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| lib.rs   | Top-level NAPI module; exports `AskarStorage`, `AskarStorageConfig`, and `KeyMethod` as NAPI classes/enums with full lifecycle methods (create, open, close, profile management). |
| kms.rs   | NAPI bindings for `AskarKms` and `AskarKeyHandle`; exposes key creation, retrieval by ID or public key, signing, verification, JWK, and algorithm enum (`KeyType`, `Alg`) bridging. |
| vault.rs | NAPI bindings for `AskarVault`; exposes credential store/get/find/delete/count operations with pagination support; defines `InnerCredential`, `InnerCredentialEntry`, `InnerCredentialMetadata`, and sort-order types for JS interop. |

## Key types / traits (if applicable)
- `AskarStorage` — NAPI class wrapping `askar::AskarStorage`.
- `AskarKms` — NAPI class wrapping `askar::kms::AskarKms` (Kms trait impl).
- `AskarKeyHandle` — NAPI class wrapping `askar::kms::AskarKeyHandle` (Key/Signer/Verifier).
- `AskarVault` — NAPI class wrapping `askar::vault::AskarVault` (Vault trait impl).
- `KeyType`, `Alg`, `InnerVCFormat`, `AskarVaultSortBy`, `AskarVaultParamsSortOrder` — NAPI enums.

## Dependencies
- Depends on: `askar` (the `plugins/askar/src` crate), `napi`, `napi-derive`, `serde_json`
- Used by: Node.js consumer code in `demos/nodejs/` and the EQUS Credentials SDK Node.js wrapper

## Constraints
- Build entry point is `plugins/askar/wrappers/nodejs/build.rs` (NAPI-RS build script).
- `unsafe` methods (`close`, `change_active_profile`) require callers to ensure no concurrent references exist.
