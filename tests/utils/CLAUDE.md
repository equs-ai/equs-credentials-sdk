# utils — Context

## Purpose
Shared infrastructure for the Equs SDK integration test suite: HTTP client emulation, test DID
resolution, static fixtures, and builder helpers consumed by all e2e test modules.

## Files / Sub-areas

| File/Dir      | Role |
|---------------|------|
| mod.rs        | Declares and re-exports `fixtures`, `helpers`, `http`, and `test_resolver` sub-modules. |
| http.rs       | `HttpClientEmulator` — URL-keyed mock `HttpClient`; dispatches requests to registered handler closures, returning 404 for unknown URLs. |
| test_resolver.rs | `TestDIDResolver` — stub `DIDResolver` for a configurable custom DID method; delegates resolution to `did:key` and rewrites the method name. |
| `fixtures/`   | Static constants and factory functions for OID4VCI and OID4VP test scenarios — see [fixtures/CLAUDE.md](fixtures/CLAUDE.md). |
| `helpers/`    | Async builder helpers for creating DIDs, key handles, and protocol participant instances — see [helpers/CLAUDE.md](helpers/CLAUDE.md). |

## Key types / traits (if applicable)
- `HttpClientEmulator` — implements `equs_sdk::http::HttpClient` for sync/async test handler dispatch.
- `TestDIDResolver` — implements `equs_sdk::did::universal::DIDResolver` for any custom method name.

## Dependencies
- Depends on: `equs_sdk` (http, did, vc, kms, nonce, inmem), `oauth2`, `ssi`, `url`, `serde_json`
- Used by: `tests/e2e/` (all modules)
