# test-fixtures — Context

## Purpose
`equs-test-fixtures` (lib target `test_fixtures`, `publish = false`) generates the secrets the SDK's tests and
demos need at runtime — keys and signed JWTs — so that none is committed as a static string. Call sites keep
their own header and payload values and pass them to one generic signer; the crate owns only the key material
and the signing.

## Files

| File | Role |
|------|------|
| `Cargo.toml` | Package manifest. Depends on `ssi`, `rsa`, `jsonwebtoken`, `serde_json` and `base64` — not on the SDK, so `ssi::JWK` is the same type on both sides and the crate builds for every target the SDK does. |
| `src/lib.rs` | `keys()` — process-wide `Keys` (`authz` RSA-2048, `issuer` / `holder` / `verifier` P-256, `secret` HS256), generated on first use. `jws(header, payload, key)` — compact JWS; `alg` is read from the header. `jwks(keys)` — public JWK Set. `did_key_url(key)` — the `did:key` URL the SDK resolves a `kid` against. |

## Key types / traits
- `Keys` — one key per role; every fixture in a process signs with the same keys, so a token and the JWKS or
  `did:key` that verifies it always agree.
- `ssi::JWK` (re-exported as `test_fixtures::JWK`) — the only key type; `JWK::to_public()` is what `jwks` publishes.

## Dependencies
- Depends on: `ssi` (P-256 generation, JWS signing, `did:key`), `rsa` (RSA generation, which `ssi` lacks),
  `jsonwebtoken` (HMAC, which `ssi` lacks), `serde_json` with `preserve_order` (headers and claims keep the
  order they are written in), `base64`
- Used by: the SDK's `[dev-dependencies]` (unit tests under `src/`, the E2E suite under `tests/`),
  `demos/multi-thread`, `demos/oid4vc/issuer`

## Constraints
- Signing panics on bad input (an `alg` the key cannot sign, a symmetric key without `k`); fixtures are test
  code, so there is no error type.
- `authz` is a fresh RSA key per process with its RFC 7638 JWK thumbprint as `kid`; a call site writes
  `authz.key_id` into its own `RS256` header, and `jwks(&[&keys().authz])` is the JWK Set to serve wherever a
  test serves the realm's JWKS.
- Every `kid` is derived from the generated key (`did_key_url` for `did:key` tokens, the thumbprint for `authz`),
  so it differs per process — a test must not hard-code one.
- RSA-2048 generation is the only slow step: the workspace root sets `opt-level = 3` for `num-bigint-dig`
  under the dev profile (tens of milliseconds instead of seconds), and `keys()` runs it once per process.
- ES256 signatures are randomised, so two calls with the same inputs give different tokens; RS256 and HS256
  are deterministic for a given key.
- Run with `cargo test -p equs-test-fixtures`; `cargo test` at the workspace root tests the root package only.
  CI runs it in `test-fixtures-test` (GitHub) and `test-fixtures-test-job` (GitLab).
