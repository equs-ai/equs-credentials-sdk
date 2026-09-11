# Core — Summary

## What this domain does
Defines every abstract interface the SDK is built on: cryptographic signing and verification, HTTP communication, key management, persistent storage, credential vaulting, and nonce generation. Nothing in this domain has a concrete implementation — it only declares traits and error types. Concrete implementations live in `inmem/` (tests/in-memory feature) and `reqwest/` (HTTP).

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| Crypto traits | `src/crypto.rs` | [src/CLAUDE.md](../src/CLAUDE.md) |
| HTTP abstraction | `src/http.rs` | [src/CLAUDE.md](../src/CLAUDE.md) |
| Key management | `src/kms.rs` | [src/CLAUDE.md](../src/CLAUDE.md) |
| Storage | `src/storage.rs` | [src/CLAUDE.md](../src/CLAUDE.md) |
| Vault | `src/vault.rs` | [src/CLAUDE.md](../src/CLAUDE.md) |
| Nonce | `src/nonce.rs` | [src/CLAUDE.md](../src/CLAUDE.md) |
| Utilities | `src/utils/` | [context](../src/utils/CLAUDE.md) |
| Reqwest HTTP impl | `src/reqwest/` | [context](../src/reqwest/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `one-core-portable` (re-exported crypto/JWE primitives), `ssi` (JWK types), `async_trait`, `snafu`, `tracing`
- Used by: every other domain — `did`, `vc`, `didcomm`, `inmem`, `wrappers`, `plugins`

## Key decisions / constraints
- `HttpClient` has a single method `async_call(Request) → Response`; all HTTP work must go through this trait, never through a concrete client directly.
- `Kms<KH>` is generic over a `KeyHandle` type parameter; consumers never hold raw key material, only opaque handles.
- `Vault` and `Storage` traits use `async_trait` with `WasmNotSend`/`WasmNotSync` bounds so they compile on both native and wasm targets.
- `Nonce` and credential types that hold sensitive data implement `ZeroizeOnDrop`.
- `HttpClient` is `#[automock]`-annotated for test mocking via `mockall`.
- `one-core-portable` (all targets) re-exports crypto, key algorithm, and JWE utilities; used on all platforms including wasm.
- `one-core` (non-wasm only) is the full platform library powering DID method implementations (`did:webvh`, `did:ethr`); its `HttpClient` trait (`get/post/send`) is incompatible with EQUS SDK's (`async_call`) — bridging requires an adapter struct (see `src/did/webvh/client.rs`).

## Error handling

Use `snafu`: `#[derive(Snafu, DebugError)]` on error enums, `#[non_exhaustive]`, snafu context selectors (`FooSnafu { ... }.build()` / `.fail()`). Include a `#[snafu(implicit)] location: Location` field on variants that wrap a source error.

## Logging

Use `tracing`. Annotate public methods with `#[instrument(level = Level::TRACE, skip(self), ret(), err())]`. Never log sensitive values (tokens, nonces).

