# Tests — Summary

## What this domain does
Contains the end-to-end (E2E) test suite and shared test utilities for EQUS Credentials SDK, plus
the `equs-test-fixtures` workspace member that mints valid JWTs and JWEs on demand. E2E tests
exercise full protocol flows (OID4VCI, OID4VP, DID resolution, DIDComm) against the real in-memory
implementations, covering scenarios that unit tests within individual modules cannot.

## Sub-areas

| Area | Path | Context file |
|------|------|--------------|
| Tests root | `tests/` | [context](../tests/CLAUDE.md) |
| E2E tests | `tests/e2e/` | [context](../tests/e2e/CLAUDE.md) |
| Shared test utilities | `tests/utils/` | [context](../tests/utils/CLAUDE.md) |
| Test fixtures | `tests/utils/fixtures/` | [context](../tests/utils/fixtures/CLAUDE.md) |
| Test helpers | `tests/utils/helpers/` | [context](../tests/utils/helpers/CLAUDE.md) |
| JWT/JWE fixture crate | `test-fixtures/` | [context](../test-fixtures/CLAUDE.md) |

## Cross-domain relationships
- Depends on: `crate::inmem` (`LocalKms`, `InMemVault`), all protocol domains (`vc`, `did`, `didcomm`), `mockall` (`MockHttpClient` via `#[automock]` on `HttpClient`)
- `equs-test-fixtures` path-depends on `equs-credentials-sdk`, which dev-depends back on it — a
  dev-dependency cycle Cargo permits and `cargo package` strips from the published manifest
- Used by: CI pipeline; not compiled into any production artifact

## Key decisions / constraints
- Run with: `cargo test --features in-memory,didcomm-http-transport`
- E2E tests use `LocalKms` / `InMemVault` — never mock the KMS.
- `MockHttpClient` (from `mockall` via `#[automock]` on `HttpClient`) is used for HTTP mocking; `mockito` is being phased out — prefer `MockHttpClient` for new tests.
- Swift wrapper tests inject `MockHttpRouter` (`wrappers/uniffi/swift/Tests/EqusSdkTests/MockHttpRouter.swift`) as the `HttpClient` instead of binding a Swifter server. It matches on URL path, so fixtures with a port baked into a signed JWT need no socket bound. `HttpTests` keeps two real-socket `ReqwestHttpClient` tests as smoke coverage.
- Parameterised tests use `rstest` `#[case]` attributes.
- Unit tests live in the same file as the code under test in a `#[cfg(test)] mod tests` block; test functions come before helper functions within the block.
- Use `#[should_panic]` for test cases that assert on expected panics.
- Tokens are built with `equs-test-fixtures`, not committed as strings. A signature-bound fixture
  cannot be edited without re-signing it — the mdoc blobs in `tests/utils/fixtures/` are the
  cautionary case.
- `scripts/scan-embedded-tokens.py` makes that claim checkable: it walks `git ls-files`, matches
  compact JWS/JWE serializations, base64url-decodes each header to confirm it (`alg`/`enc`) rather
  than regex-guess, and separately flags a JWK carrying a `d` member or a PEM `PRIVATE KEY` block.
  `--fail-on PATH…` exits non-zero if a hit falls under one of the given paths.
- `src/`, `tests/`, `plugins/askar/src`, `wrappers/nodejs`, `wrappers/test` and `wrappers/uniffi` are
  clean (`python3 scripts/scan-embedded-tokens.py --fail-on src/ tests/ plugins/askar/src
  wrappers/nodejs wrappers/test wrappers/uniffi` exits 0). `demos/multi-thread/src/main.rs` and
  `demos/oid4vc/issuer/src/main.rs` each keep one accepted exception (expired localhost Keycloak
  token `validate_scope` reads via `decode_unverified`); `plugins/askar/wrappers/nodejs` still holds
  two committed tokens (out of scope for this migration).
- Phase B bridge: `equs-test-fixtures` ships a `fixture_gen` binary
  (`test-fixtures/src/bin/fixture_gen.rs`, driven by `test-fixtures/src/bundle.rs`) that mints every
  fixture the non-Rust wrapper suites need — `authRequestJwt`, `vc`, `vp`, `statusListJwt`,
  `vcWithStatus`, `accessToken`, `proofJwt`, `sdJwtCreds`, `authResponseJwe`, `dsdJwtGrantVpToken`,
  `revokedStatusListJwt`, `vcRevoked` — and writes them to a gitignored JSON file
  (`fixtures.generated.json`). `statusListJwt`/`vcWithStatus` and `revokedStatusListJwt`/`vcRevoked`
  are two independently coherent Valid/revoked pairs at two different URLs, so a wrapper test can
  exercise status filtering without hand-rolling a status list. `dsdJwtGrantVpToken` needs
  `--features delegate-sd-jwt`; `bundle::build()` fails loudly rather than silently omitting it.
  The TypeScript (`wrappers/nodejs`, `wrappers/test/js_common`), Kotlin (`wrappers/uniffi/kotlin`)
  and Swift (`wrappers/uniffi/swift`) suites now read this bundle (`EQUS_FIXTURE_BUNDLE`) instead of
  holding committed tokens. Two fixed-URL pairs the bundle publishes at `https://issuer.example/…`
  are unreachable from a suite whose mock server binds a real `localhost` port or socket (TS's Jest
  mock server, Kotlin's `MockWebServer`): those suites mint an equivalent pair in-process instead
  (Kotlin's status pair via `VcCoreStatusIssuer`/`VcCoreIssuer`, mirroring `VcCoreTest.kt`). Swift's
  `MockHttpRouter` matches routes on URL path only (see below), so it does not have this problem —
  the bundle's `vcWithStatus`/`statusListJwt` pair is used directly. `revokedStatusListJwt`/
  `vcRevoked` remain unconsumed by any suite (no wrapper test exercises revocation); they would be
  reachable in Swift the same way but are not otherwise. Only CI wiring (generating the bundle
  before each wrapper job) remains.
- `cargo test --all-features` at the workspace root tests the root package only, so
  `equs-test-fixtures` runs in its own CI job (`test-fixtures-test`, `test-fixtures-test-job`).
- SDK types do not unify across the fixture crate's dev-dependency cycle: a `src/` unit test builds
  a fixture's inputs through `test_fixtures::equs_sdk::…` and carries only the token string back.
