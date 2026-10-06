# Tests — Summary

## What this domain does
Contains the end-to-end (E2E) test suite and shared test utilities for EQUS Credentials SDK. E2E tests exercise full protocol flows (OID4VCI, OID4VP, DID resolution, DIDComm) against the real in-memory implementations, covering scenarios that unit tests within individual modules cannot.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| Tests root | `tests/` | [context](../tests/CLAUDE.md) |
| E2E tests | `tests/e2e/` | [context](../tests/e2e/CLAUDE.md) |
| Shared test utilities | `tests/utils/` | [context](../tests/utils/CLAUDE.md) |
| Test fixtures | `tests/utils/fixtures/` | [context](../tests/utils/fixtures/CLAUDE.md) |
| Test helpers | `tests/utils/helpers/` | [context](../tests/utils/helpers/CLAUDE.md) |
| Runtime fixtures crate | `test-fixtures/` | [context](../test-fixtures/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `crate::inmem` (`LocalKms`, `InMemVault`), all protocol domains (`vc`, `did`, `didcomm`), `test_fixtures` (keys and signed JWTs generated at runtime), `mockall` (`MockHttpClient` via `#[automock]` on `HttpClient`)
- Used by: CI pipeline; not compiled into any production artifact

## Key decisions / constraints
- Run with: `cargo test --features in-memory,didcomm-http-transport`
- Signed and encrypted fixtures (access tokens, proof JWTs, status-list tokens, the OID4VP request object, SD-JWT VCs and their key-bound presentations, the encrypted authorization response) and X.509 test PKIs are generated at test runtime through `test_fixtures` (`jws`, `sd_jwt`, `sd_jwt_kb`, `jwe`, `x509`, `jwks`, `did_key_url`, `did_key`), with the header and payload values written at the call site, and `crate::utils::test_utils` shares the status-list token and the trusted-anchor map across modules; the recorded tokens they replace are gone from the Rust tests and demos. The mdoc IACA certificates in `tests/utils/fixtures/oid4vp.rs` stay recorded, because the recorded mdoc presentations are signed under them. Every `kid` is derived from the generated key, so tests never hard-code one. `cargo test -p equs-test-fixtures` runs that crate's own tests (CI: `test-fixtures-test`, `test-fixtures-test-job`) — the root `cargo test` does not build it.
- The JS suites (`wrappers/nodejs/test`, `wrappers/test/js_common`, `plugins/askar/wrappers/nodejs/test`) build the same kinds of fixtures through the Node.js wrapper's `fixture*` functions (cargo feature `test-fixtures`, see `claude/wrappers.md`), with the recorded header, claim and disclosure values kept at the call site.
- E2E tests use `LocalKms` / `InMemVault` — never mock the KMS.
- `MockHttpClient` (from `mockall` via `#[automock]` on `HttpClient`) is used for HTTP mocking; `mockito` is being phased out — prefer `MockHttpClient` for new tests.
- Swift wrapper tests inject `MockHttpRouter` (`wrappers/uniffi/swift/Tests/EqusSdkTests/MockHttpRouter.swift`) as the `HttpClient` instead of binding a Swifter server. It matches on URL path, so fixtures with a port baked into a signed JWT need no socket bound. `HttpTests` keeps two real-socket `ReqwestHttpClient` tests as smoke coverage.
- Parameterised tests use `rstest` `#[case]` attributes.
- Unit tests live in the same file as the code under test in a `#[cfg(test)] mod tests` block; test functions come before helper functions within the block.
- Use `#[should_panic]` for test cases that assert on expected panics.
