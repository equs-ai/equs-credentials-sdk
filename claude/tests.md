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
- `src/`, `tests/`, `plugins/`, `wrappers/nodejs`, `wrappers/test` and `wrappers/uniffi` are clean
  (`python3 scripts/scan-embedded-tokens.py --fail-on src/ tests/ plugins/ wrappers/nodejs
  wrappers/test wrappers/uniffi` exits 0). `demos/multi-thread/src/main.rs` and
  `demos/oid4vc/issuer/src/main.rs` each keep one accepted exception (expired localhost Keycloak
  token `validate_scope` reads via `decode_unverified`). `plugins/askar/wrappers/nodejs`'s two
  committed tokens (`test/vault.test.ts`) were migrated in Task 12's fix round: the audit had missed
  them, the same way it missed the 11 backslash-continued tokens in `src/` that Task 8b caught — a
  package CI actually tests (`askar-plugin-nodejs-test`, `askar-plugin-nodejs-test-job`) is not
  out of scope just because it sits under `plugins/`. It now has its own `pretest`/`fixtures` npm
  scripts (mirroring `wrappers/nodejs`) and its own loader
  (`plugins/askar/wrappers/nodejs/test/fixtures.ts`, same shape as `wrappers/test/js_common`'s);
  `CREDENTIAL_DATA.credential.payload` in `vault.test.ts` is now the bundle's `vp.presentation`
  (a full SD-JWT VP — VC, disclosures and KB-JWT — the closest bundle shape to what it replaced).
  `AskarVault` never parses the credential string it stores (`create_entry` in
  `plugins/askar/src/vault.rs` takes it as an opaque `&str`), so no assertion depended on its
  content and none needed to change.
- Phase B bridge: `equs-test-fixtures` ships a `fixture_gen` binary
  (`test-fixtures/src/bin/fixture_gen.rs`, driven by `test-fixtures/src/bundle.rs`) that mints every
  fixture the non-Rust wrapper suites need — `vc`, `vp`, `statusListJwt`, `vcWithStatus`,
  `accessToken`, `proofJwt`, `sdJwtCreds`, `authResponseJwe` — and writes them to a gitignored JSON
  file (`fixtures.generated.json`). `authRequestJwt` and `dsdJwtGrantVpToken` were removed from the
  bundle (a whole-branch review found zero live TS/Kotlin/Swift consumers of either; each wrapper
  mints its own OID4VP request object or delegated grant in-process instead), which also means
  generating the bundle no longer needs `--features delegate-sd-jwt` / `--all-features` — none of
  the five `fixture_gen` invocations (`wrappers/nodejs/package.json`,
  `plugins/askar/wrappers/nodejs/package.json`, the two `wasm-test` CI lines,
  `wrappers/uniffi/scripts/generate_fixtures.sh`, the Gradle `fixtureGen` task) pass it anymore. The
  TypeScript (`wrappers/nodejs`, `wrappers/test/js_common`), Kotlin (`wrappers/uniffi/kotlin`)
  and Swift (`wrappers/uniffi/swift`) suites now read this bundle (`EQUS_FIXTURE_BUNDLE`) instead of
  holding committed tokens. A fixed-URL pair the bundle publishes at `https://issuer.example/…` is
  unreachable from a suite whose mock server binds a real `localhost` port or socket (TS's Jest mock
  server, Kotlin's `MockWebServer`): those suites mint an equivalent pair in-process instead (Kotlin's
  status pair via `VcCoreStatusIssuer`/`VcCoreIssuer`, mirroring `VcCoreTest.kt`). Swift's
  `MockHttpRouter` matches routes on URL path only (see below), so it does not have this problem —
  the bundle's `vcWithStatus`/`statusListJwt` pair is used directly. An earlier revision also shipped
  a second, independently coherent `revokedStatusListJwt`/`vcRevoked` pair; it was removed (Task 12)
  once two reviews confirmed no TypeScript, Kotlin or Swift suite consumed it — Swift could have
  reached it the same way it reaches `vcWithStatus`/`statusListJwt`, but nothing did. CI now
  generates the bundle before every wrapper job that reads it (Task 12): Node's `pretest` covers
  `wrappers/nodejs` and, in the same job, `wrappers/test/js_common`'s `test:nodejs`; the `wasm-test`
  job generates it explicitly before `test:wasm` since it never runs the Node suite first; Gradle's
  `fixtureGen` task (`dependsOn` on `tasks.test`) covers Kotlin; `wrappers/uniffi/Makefile`'s
  `ios-generate-fixtures` target, now a prerequisite of `ios-test-only`, covers Swift in both
  `make ios-test` (GitLab) and `make ios-test-only` (GitHub Actions); and `plugins/askar/wrappers/nodejs`
  has its own `pretest`/`fixtures` scripts, which fire on `npm run test --prefix
  plugins/askar/wrappers/nodejs` — the exact invocation both `askar-plugin-nodejs-test` and
  `askar-plugin-nodejs-test-job` already used, so neither CI file needed a script-line change, only
  the package's own `package.json`.
- `cargo test --all-features` at the workspace root tests the root package only, so
  `equs-test-fixtures` runs in its own CI job (`test-fixtures-test`, `test-fixtures-test-job`).
- `scripts/scan-embedded-tokens.py --fail-on src/ tests/ plugins/ wrappers/` runs as a tier-1 CI job
  (`scan-embedded-tokens`, `scan-embedded-tokens-job`) beside `fmt`, alongside
  `scripts/test_scan_embedded_tokens.py`. An earlier draft narrowed this to `plugins/askar/src`
  because `plugins/askar/wrappers/nodejs` still held two committed tokens; that was routing the gate
  around a live gap instead of closing it, so those two tokens were migrated instead (see above) and
  the full `plugins/` is what's actually gated now. GitLab's job image is `rust:${RUST_VERSION}-bookworm`
  (matches the rest of the pipeline) — `python:3-slim` shipped no `git`, which `git_tracked_files()`
  needs, and failed every run indistinguishably from a real hit (both exited `1`); the scanner now
  raises `ScanEnvironmentError` and exits `3` when `git` is missing, never `1`.
- SDK types do not unify across the fixture crate's dev-dependency cycle: a `src/` unit test builds
  a fixture's inputs through `test_fixtures::equs_sdk::…` and carries only the token string back.
