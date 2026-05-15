# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build (exclude WASM which requires wasm-pack)
cargo build --all-features --workspace --exclude wasm

# Run all tests
cargo test --all-features

# Run a single test by name
cargo test --all-features <test_name>

# Run tests with coverage
cargo tarpaulin --skip-clean --timeout 180 --all-features

# Lint
cargo fmt --all -- --check
cargo clippy --workspace --exclude wasm --all-targets --all-features -- -Dwarnings

# Generate docs
cargo doc --no-deps
```

Git hooks run `fmt` and `clippy` on pre-push via [lefthook](https://lefthook.dev/) (`lefthook.yml`).

## Architecture

This is an SSI (Self-Sovereign Identity) **library**, not an application. Consumers must provide their own implementations of `KmsService`, `VaultService`, and OID4VC endpoint handlers. The `inmem/` module ships reference implementations for testing and demos.

### Core modules (`src/`)

| Module | Purpose |
|--------|---------|
| `vc/` | Verifiable Credentials — OID4VCI issuance, OID4VP presentation, SD-JWT, JSON-LD, mDL formats, DIF Presentation Exchange, DCQL, Token Status List revocation |
| `did/` | DID resolution — `did:key`, `did:web`, `did:peer`, `did:webvh`, universal resolver |
| `didcomm/` | DIDComm V2 messaging (agents, connections, protocols, transports) — **not available on WASM** |
| `inmem/` | In-memory KMS, Vault, and storage — for demos and tests only |
| `kms.rs`, `vault.rs`, `storage.rs` | Core trait definitions that consumers implement |
| `crypto.rs` | Cryptographic operations (JWS/JWE, key generation) |
| `utils/` | JWK, base64, serde helpers, X.509 trust store |

### Workspace members

- `common-macros/` — `DebugError` procedural macro (used with `snafu` throughout the codebase)
- `plugins/askar/` — Optional Aries-Askar KMS/Vault integration
- `wrappers/nodejs/` — Node.js FFI bindings
- `wrappers/wasm/` — WebAssembly bindings
- `wrappers/uniffi/` — Kotlin/Swift bindings via UniFFI
- `demos/` — OID4VC flows in Rust, Node.js, WASM, Android, iOS

### Feature flags (Cargo.toml)

- `in-memory` — enables `inmem/` KMS/Vault
- `didcomm-http-transport` — HTTP transport for DIDComm
- `test-utils` — exposes test helpers

### Error handling & logging

All errors use `snafu` with the `DebugError` derive macro from `common-macros/`. Structured logging uses `tracing`.

### Tests

End-to-end integration tests live in `tests/e2e/`. Test fixtures are in `tests/utils/fixtures/`. The mocking stack uses `mockall`, `mockito`, and `httpmock`.
