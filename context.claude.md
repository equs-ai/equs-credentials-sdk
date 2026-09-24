# EQUS Credentials SDK — Context Index

> **Maintenance rule:** Update this file whenever any `claude/*.md` changes.
> Add a one-line entry if a new `claude/*.md` is added; remove if deleted.
> When a source file, directory, or domain changes, follow the update protocol in `CONTEXT_PLAN.md`.

## How to navigate

Start here → pick a domain → follow the link to `claude/<domain>.md` →
that file lists every sub-area with a link to the relevant `CLAUDE.md` inside the source tree.

## Domains

| Domain | Covers | Detail |
|--------|--------|--------|
| Core traits | `HttpClient`, `Kms`, `Storage`, `Vault`, `NonceHandler`, `crypto`, `utils`, `reqwest` | [claude/core.md](claude/core.md) |
| DID | `did:key`, `did:peer`, `did:web`, `did:webvh`, `did:ethr`, `UniversalResolver` | [claude/did.md](claude/did.md) |
| VC | `Issuer`/`Holder`/`Verifier` core, OID4VCI, OID4VP, SD-JWT, DCQL, Presentation Exchange, status formats | [claude/vc.md](claude/vc.md) |
| DIDComm | `Agent` runtime, connection lifecycle, envelope crypto, Aries issuance + present-proof, OOB, transports | [claude/didcomm.md](claude/didcomm.md) |
| In-memory | `LocalKms`, `InMemVault`, `InMemStorage`, `LocalNonceHandler`, crypto key impls | [claude/inmem.md](claude/inmem.md) |
| Wrappers | Node.js (NAPI-RS), WASM (wasm-bindgen), Kotlin/Swift (UniFFI) | [claude/wrappers.md](claude/wrappers.md) |
| Plugins | Askar secure-storage plugin (KMS + Vault backed by `aries-askar`) | [claude/plugins.md](claude/plugins.md) |
| Tests | E2E test suite, shared fixtures and helpers | [claude/tests.md](claude/tests.md) |
| Demos | OID4VC (issuer/holder/verifier), multi-thread, Node.js, WASM, Android, iOS, Keycloak | [claude/demos.md](claude/demos.md) |
| CI/CD | GitHub Actions CI and the crates.io release | [.github/CLAUDE.md](.github/CLAUDE.md) |
| Release | Release-pipeline scripts, release manifest | [scripts/CLAUDE.md](scripts/CLAUDE.md) |

## Repository layout (quick reference)

```
equs-credentials-sdk/
├── .github/              # GitHub Actions CI
├── src/                  # Core SDK library
│   ├── crypto.rs         # Signing/verifying key traits
│   ├── http.rs           # HttpClient trait
│   ├── kms.rs            # Kms / KeyHandle traits
│   ├── storage.rs        # Storage<K,V> trait
│   ├── vault.rs          # Vault trait
│   ├── nonce.rs          # NonceHandler trait
│   ├── did/              # DID methods + UniversalResolver
│   ├── vc/               # Verifiable Credentials stack
│   ├── didcomm/          # DIDComm V2 protocol engine (non-wasm)
│   ├── inmem/            # In-memory implementations (test/feature)
│   ├── reqwest/          # Concrete HttpClient over reqwest
│   └── utils/            # Shared utilities
├── wrappers/
│   ├── nodejs/           # NAPI-RS → Node.js
│   ├── uniffi/           # UniFFI → Kotlin + Swift
│   └── wasm/             # wasm-bindgen → browser/WASM
├── plugins/
│   └── askar/            # Askar secure-storage plugin
├── equs-common-macros/   # DebugError derive (lib target: common_macros)
├── tests/
│   ├── e2e/              # End-to-end test suite
│   └── utils/            # Shared test fixtures + helpers
├── scripts/              # Release-pipeline scripts
├── demos/                # Example applications
├── claude/               # Domain summary files (Phase 3)
└── context.claude.md     # ← you are here
```

## Key cross-cutting constraints

| Constraint | Scope |
|------------|-------|
| Non-wasm only | `src/didcomm/`, `src/did/didethr/`, `src/did/webvh/`, UniFFI wrapper |
| Feature-gated (`in-memory`) | `src/inmem/` |
| Feature-gated (`didcomm-http-transport`) | `src/didcomm/transport/http/` |
| Feature-gated (`delegate-sd-jwt`, experimental) | `src/vc/formats/dsd_jwt.rs`, `src/vc/oid4vp/delegate.rs`, per-credential delegation in `present_credentials(_auto)` + `Verifier::verify_and_extract_presentation` + core `create_delegated_presentation` |
| `ZeroizeOnDrop` on sensitive types | `Nonce`, `Credential`, `Claims` |
| All HTTP must go through `HttpClient` | Entire SDK |
| No raw key material — only `KeyHandle` | All KMS consumers |

## Published package names

| Target | Package | Source |
|--------|---------|--------|
| crates.io | `equs-credentials-sdk` | `Cargo.toml` (lib target stays `equs_sdk`, so imports remain `use equs_sdk::…`). Published by `.github/workflows/publish-crate.yml` on a `vX.Y.Z` tag. |
| crates.io | `equs-common-macros` | `equs-common-macros/Cargo.toml` (lib target stays `common_macros`, so imports remain `use common_macros::…`). Published by `.github/workflows/publish-common-macros.yml` on a `common-macros/vX.Y.Z` tag (prerelease suffix allowed). |
| Node.js | `@equs-ai/equs-credentials-sdk` | `wrappers/nodejs/package.json` (napi binary `equs-credentials-sdk`). Published to npmjs with its three platform packages by `.github/workflows/publish-nodejs.yml` on a `nodejs/vX.Y.Z` tag. |
| WASM | `@equs-ai/equs-credentials-sdk-wasm` | `wrappers/wasm/package.json`. Published to npmjs by `.github/workflows/publish-wasm.yml` on a `wasm/vX.Y.Z` tag. |
| iOS | `equs-credentials-sdk` | `wrappers/uniffi/swift/Package.swift` (product/module stays `EqusSdk`) |
| Kotlin | `com.equs.credentials` | `wrappers/uniffi/uniffi.toml` (AAR artifact `equs-credentials-sdk-android`) |
| Askar plugin (Node.js) | `@equs-ai/equs-credentials-sdk-askar-storage` | `plugins/askar/wrappers/nodejs/package.json`. Published to npmjs with its three platform packages by `.github/workflows/publish-askar.yml` on an `askar/vX.Y.Z` tag. |
