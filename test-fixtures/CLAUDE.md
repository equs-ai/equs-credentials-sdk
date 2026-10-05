# test-fixtures — Context

## Purpose
`equs-test-fixtures` (lib target `test_fixtures`, `publish = false`) mints a valid token of each
JWT kind the SDK's tests need, plus a JWE, signed at test runtime with sane defaults and per-test
overrides. It exists so that a test needing, say, an SD-JWT VC with one claim moved does not have to
rebuild the signing scaffolding, and so that `tests/` can reach fixtures that `src/utils/test_utils.rs`
(`#[cfg(test)] pub(crate)`) keeps private.

No committed static token strings: a signature-bound fixture cannot be edited without re-signing it,
and `tests/utils/fixtures/` mdoc blobs already show what that costs.

`src/generator.rs` mints the fixtures the wrapper suites need in-process, from one set of keys. The
Node, WASM and UniFFI bindings export it as `FixtureGenerator` in their test builds.

## Files

| File | Role |
|------|------|
| `src/lib.rs` | Crate root; module declarations, `Error`/`Result` re-exports, and the `equs_sdk` re-export |
| `src/generator.rs` | `Generator` — owns one `LocalKms` and the issuer, holder and verifier keys; mints an SD-JWT VC, a presentation, a status-list pair served at a caller-chosen URL, an access token, a PoP JWT and an auth-response JWE on demand |
| `src/error.rs` | `Error` / `Result` — `Kms`, `Did`, `Signing`, `Json`, `Sdk` variants |
| `src/keys.rs` | `FixtureKey` — a `LocalKms` key handle plus its `did:key`, DID URL and `KeyMetadata`; covers all four `KeyType`s |
| `src/claims.rs` | Shared claim defaults (`DEFAULT_AUDIENCE`, `DEFAULT_NONCE`, …) and `now()` / `from_now()` |
| `src/jws.rs` | `sign_compact` / `sign_compact_with_header` — compact JWS assembly over `crypto::Signer` |
| `src/http.rs` | `StaticHttpClient` — URL-keyed `HttpClient` stub; `404` for anything unregistered |
| `src/access_token.rs` | `AccessToken` — OAuth 2.0 bearer access token (`typ: JWT`); signed ES256 since `LocalKms` has no RSA, so tests assert on claims rather than `alg` |
| `src/pop.rs` | `ProofOfPossession` — OID4VCI `openid4vci-proof+jwt` |
| `src/sd_jwt_vc.rs` | `SdJwtVc` — issuer-signed SD-JWT VC, via `VCFormatsSdJwtAPI::create_vc` |
| `src/x509.rs` | (feature `x509`) `X509Chain` — self-signed P-256 leaf certificate (via `rcgen`) certifying a `FixtureKey`, plus `sign_sd_jwt_vc` to mint the SD-JWT VC that carries it in `x5c` |
| `src/kb_jwt.rs` | `KbJwt` — SD-JWT VP with a `kb+jwt`, via `vc::core::HolderService::create_presentation` |
| `src/status_list.rs` | `StatusListToken` — `statuslist+jwt`, via `StatusListJwt::create_status_list` |
| `src/request_object.rs` | `RequestObject` — OID4VP signed request object (`oauth-authz-req+jwt`) |
| `src/id_token.rs` | `IdToken` — SIOP `id_token` (`typ: JWT`) |
| `src/jwe.rs` | `Jwe` — encrypted response, via `vc::oid4vp::jwe::JweEncryptor` |
| `tests/round_trip.rs` | Round-trip + failure case for every kind whose verifier is public |
| `tests/generator.rs` | A `Generator` status pair resolves Valid at the URL it was minted for; its fixtures share the generator's keys |
| `tests/x509.rs` | `X509Chain` checks; feature `x509` |
| `tests/util/mod.rs` | Unverified header/payload decoding for claim assertions |

## Key types / traits
- `FixtureKey` — the only source of key material; every builder signs through its `KeyHandle`.
- One builder type per kind, all `Kind::builder(..) → … → .build().await`. Required arguments are
  that kind's required inputs, so a missing one is a compile error rather than a runtime failure.
- `StaticHttpClient` — for the two entry points that demand an `HttpClient` and never call it, and
  for serving a status list token back to the status verifier.

## Dependencies
- Depends on: `equs-credentials-sdk` (path, `in-memory`), `base64`, `serde_json`, `async-trait`,
  `snafu`; `rcgen` under feature `x509`, on by default.
- Used by: the wrapper bindings, with default features off — `wrappers/nodejs` and
  `wrappers/uniffi` under their `test-fixtures` feature, `wrappers/wasm` under `test-utils`.

## Constraints
- Run with `cargo test --all-features -p equs-test-fixtures`. `cargo test --all-features` at the
  workspace root tests the root package only and never builds this crate; CI has its own job
  (`test-fixtures-test`, `test-fixtures-test-job`).
- With default features off the crate builds for `wasm32-unknown-unknown`; `rcgen` (via `ring`) is
  what `x509` keeps out. The consumer supplies `getrandom`'s `wasm_js` feature.
- Positive fixtures only. Malformed-token generation stays in the error-path tests that need it.
- `vc::pop` is private and `vc::formats` is `pub(crate)`, so the PoP, request object and `id_token`
  claim sets are assembled here rather than taken from an SDK constructor, and their verifiers are
  not reachable from this crate's tests.
- ECDH-ES is the only key management the SDK's `JweEncryptor` supports, so a JWE recipient key must
  be `P256`.
- `publish = false`. The crate is never released.
