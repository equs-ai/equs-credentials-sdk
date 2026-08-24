# src — Context

## Purpose
Root of the Equs SDK Rust library. Defines the core trait interfaces (crypto, HTTP, KMS, storage, vault, nonce) that the rest of the SDK builds on, and re-exports all functional modules.

## Files

| File | Role |
|------|------|
| `lib.rs` | Crate root; feature-gates modules and controls public re-exports |
| `crypto.rs` | `SigningKey`, `VerifyingKey`, `Key` traits; `KeyType` enum; `JWK` type alias; crypto `Error` |
| `http.rs` | `HttpClient` trait (`async_call`) — the single HTTP abstraction used throughout the SDK; `#[automock]` for tests |
| `jwe.rs` | `JweDecrypt`/`JweDecryptBytes` KMS-backed JWE decryption via `KeyAgreement`; impl machinery is native-only (see Constraints) |
| `kms.rs` | `Kms<KH>` and `DerivativeKms` traits; `KeyHandle` supertrait; `KeyMetadata`; `KeyType` enum; `#[automock]` |
| `nonce.rs` | `NonceHandler` trait; `Nonce` newtype (zeroize-on-drop) |
| `storage.rs` | `Storage<K, V>` trait — generic async key-value store with transaction support |
| `vault.rs` | `Vault` trait — credential store with query/filter support; `VaultQuery`, `CredentialFilter`; `#[automock]` |
| `did/` | DID methods + `UniversalResolver` — see [did/CLAUDE.md](did/CLAUDE.md) |
| `didcomm/` | DIDComm V2 protocol engine (non-wasm only) — see [didcomm/CLAUDE.md](didcomm/CLAUDE.md) |
| `inmem/` | In-memory implementations of all traits (test + `in-memory` feature) — see [inmem/CLAUDE.md](inmem/CLAUDE.md) |
| `reqwest/` | Concrete `HttpClient` over `reqwest` — see [reqwest/CLAUDE.md](reqwest/CLAUDE.md) |
| `utils/` | Shared utilities (base64, wasm compat shims, etc.) — see [utils/CLAUDE.md](utils/CLAUDE.md) |
| `vc/` | Verifiable Credentials — issuance, presentation, OID4VCI, OID4VP, formats — see [vc/CLAUDE.md](vc/CLAUDE.md) |

## Key types / traits
- `HttpClient` — single-method `async_call(Request) → Response` trait; all HTTP work must go through this.
- `Kms<KH>` — generate, export, sign, verify; `KH` is a type-erased key handle.
- `DerivativeKms` — extends `Kms` with BIP32, ECDH-1PU, and ECDH-ES derivation.
- `Storage<K, V>` — async CRUD + transaction; backing store for KMS, connection, and VC state.
- `Vault` — stores and queries `Credential` objects with JSONPath-style filtering.
- `NonceHandler` — generates, validates and invalidates nonces.
- `SigningKey` / `VerifyingKey` / `Key` — crypto primitive traits implemented by key handles in `inmem`.

## Dependencies
- Depends on: `one-core-asdk` (re-exported crypto + JWE), `ssi` (DID/JWK types), `async_trait`, `snafu`, `tracing`
- One-core (non-wasm only): `one-core` via DID method implementations in `did/`

## Constraints
- `didcomm` module is non-wasm only (`#[cfg(not(target_arch = "wasm32"))]`).
- `jwe` module: only the `JweDecrypt` trait declaration is cross-target; the blanket impls, `decrypt_jwe*` functions, and the `PrivateKeyAgreementHandle` bridge are non-wasm only. one_core's `PrivateKeyAgreementHandle` requires `Send` futures, which the `?Send` wasm `KeyAgreement` cannot satisfy; wasm never drives JWE decryption.
- `inmem` module is gated by `#[cfg(any(test, feature = "in-memory"))]`.
- `reqwest` sub-module for wasm targets uses a wasm-compatible HTTP backend.
