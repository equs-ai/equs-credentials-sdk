# test-fixtures — Context

## Purpose
`equs-test-fixtures` (lib target `test_fixtures`, `publish = false`) mints a valid token of every
JWT kind the SDK handles, plus a JWE, signed at test runtime with sane defaults and per-test
overrides. It exists so that a test needing, say, an SD-JWT VC with one claim moved does not have to
rebuild the signing scaffolding, and so that `tests/` can reach fixtures that `src/utils/test_utils.rs`
(`#[cfg(test)] pub(crate)`) keeps private.

No committed static token strings: a signature-bound fixture cannot be edited without re-signing it,
and `tests/utils/fixtures/` mdoc blobs already show what that costs.

## Files

| File | Role |
|------|------|
| `src/lib.rs` | Crate root; module declarations, `Error`/`Result` re-exports, and the `equs_sdk` re-export the SDK's own unit tests go through |
| `src/error.rs` | `Error` / `Result` — `Kms`, `Did`, `Signing`, `Json`, `Sdk` variants |
| `src/keys.rs` | `FixtureKey` — a `LocalKms` key handle plus its `did:key`, DID URL and `KeyMetadata`; covers all four `KeyType`s |
| `src/claims.rs` | Shared claim defaults (`DEFAULT_AUDIENCE`, `DEFAULT_NONCE`, …) and `now()` / `from_now()` |
| `src/jws.rs` | `sign_compact` / `sign_compact_with_header` — compact JWS assembly over `crypto::Signer` |
| `src/http.rs` | `StaticHttpClient` — URL-keyed `HttpClient` stub; `404` for anything unregistered |
| `src/pop.rs` | `ProofOfPossession` — OID4VCI `openid4vci-proof+jwt` |
| `src/sd_jwt_vc.rs` | `SdJwtVc` — issuer-signed SD-JWT VC, via `VCFormatsSdJwtAPI::create_vc` |
| `src/kb_jwt.rs` | `KbJwt` — SD-JWT VP with a `kb+jwt`, via `vc::core::HolderService::create_presentation` |
| `src/dsd_jwt.rs` | `DsdJwt` — delegation grant, via `HolderService::create_delegated_credential`; feature `delegate-sd-jwt` |
| `src/status_list.rs` | `StatusListToken` — `statuslist+jwt`, via `StatusListJwt::create_status_list` |
| `src/request_object.rs` | `RequestObject` — OID4VP signed request object (`oauth-authz-req+jwt`) |
| `src/id_token.rs` | `IdToken` — SIOP `id_token` (`typ: JWT`) |
| `src/vp_token.rs` | `VpToken` — the `vp_token` JSON value wrapping one SD-JWT VP |
| `src/jwe.rs` | `Jwe` — encrypted response, via `vc::oid4vp::jwe::JweEncryptor` |
| `tests/round_trip.rs` | Round-trip + failure case for every kind whose verifier is public |
| `tests/delegation.rs` | The same for `dsd_jwt`; gated on `delegate-sd-jwt` |
| `tests/util/mod.rs` | Unverified header/payload decoding for claim assertions |

## Key types / traits
- `FixtureKey` — the only source of key material; every builder signs through its `KeyHandle`.
- One builder type per kind, all `Kind::builder(..) → … → .build().await`. Required arguments are
  that kind's required inputs, so a missing one is a compile error rather than a runtime failure.
- `StaticHttpClient` — for the two entry points that demand an `HttpClient` and never call it, and
  for serving a status list token back to the status verifier.

## Dependencies
- Depends on: `equs-credentials-sdk` (path, `in-memory`), `base64`, `serde_json`, `async-trait`,
  `snafu`; `tokio` (dev).
- Used by: `equs-credentials-sdk` `[dev-dependencies]` — a dev-dependency cycle, which Cargo permits
  and which `cargo package` strips from the published manifest.

## Constraints
- Run with `cargo test --all-features -p equs-test-fixtures`. `cargo test --all-features` at the
  workspace root tests the root package only and never builds this crate; CI has its own job
  (`test-fixtures-test`, `test-fixtures-test-job`).
- **SDK types do not unify across the dev-dependency cycle.** Building the SDK's test target
  compiles `equs_sdk` twice — once as this crate's dependency, once as the `cfg(test)` crate under
  test — so a `src/` unit test cannot pass a `crate::inmem::kms::LocalKms` to a builder. It
  constructs inputs through `test_fixtures::equs_sdk::…` and carries only the token `String` back.
  See `src/vc/pop/jwt_pop.rs`, `src/vc/oid4vp/verifier.rs`, `src/vc/oid4vp/holder.rs`.
- Positive fixtures only. Malformed-token generation stays in the error-path tests that need it.
- `vc::pop` is private and `vc::formats` is `pub(crate)`, so the PoP, request object and `id_token`
  claim sets are assembled here rather than taken from an SDK constructor. Their round-trips
  therefore live in the SDK's own unit tests, where the verifiers are reachable.
- ECDH-ES is the only key management the SDK's `JweEncryptor` supports, so a JWE recipient key must
  be `P256`.
- `publish = false`. The crate is never released.
