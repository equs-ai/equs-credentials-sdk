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

## Cross-domain relationships
- Depends on: `crate::inmem` (`LocalKms`, `InMemVault`), all protocol domains (`vc`, `did`, `didcomm`), `mockall` (`MockHttpClient` via `#[automock]` on `HttpClient`)
- Used by: CI pipeline; not compiled into any production artifact

## Key decisions / constraints
- Run with: `cargo test --features in-memory,didcomm-http-transport`
- E2E tests use `LocalKms` / `InMemVault` — never mock the KMS.
- `MockHttpClient` (from `mockall` via `#[automock]` on `HttpClient`) is used for HTTP mocking; `mockito` is being phased out — prefer `MockHttpClient` for new tests.
- Parameterised tests use `rstest` `#[case]` attributes.
- Unit tests live in the same file as the code under test in a `#[cfg(test)] mod tests` block; test functions come before helper functions within the block.
- Use `#[should_panic]` for test cases that assert on expected panics.
