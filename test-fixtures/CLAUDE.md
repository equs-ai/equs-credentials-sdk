# test-fixtures — Context

## Purpose
`equs-test-fixtures` (lib target `test_fixtures`, `publish = false`) generates the secrets the SDK's tests and
demos need at runtime — keys, and the fixtures built on them — so that none is committed as a static string.
Call sites keep their own header, claim and parameter values and pass them to one generic builder per fixture
kind; the crate owns only the key material and the cryptography.

## Files

| File | Role |
|------|------|
| `Cargo.toml` | Package manifest. Depends on `ssi`, `rsa`, `jsonwebtoken`, `sha2`, `equs-one-core-crypto`, `serde`, `serde_json` and `base64`, plus `rcgen` and `p256` behind the default-on `x509` feature — not on the SDK, so `ssi::JWK` is the same type on both sides and the crate builds for every target the SDK does. |
| `src/lib.rs` | `keys()` — process-wide `Keys` (`authz` RSA-2048, `issuer` / `holder` / `verifier` P-256, `secret` HS256), each a `LazyLock` generated on first use. `jws(header, payload, key)` — compact JWS; `alg` is read from the header. `jwks(keys)` — public JWK Set. `did_key_url(key)` / `did_key(key)` — the `did:key` URL the SDK resolves a `kid` against, and the bare DID for `iss`, `sub` or `aud`. `sd_jwt(header, claims, disclosures, key)` — issuer-signed SD-JWT: `_sd` holds the sorted digests of the disclosures, given as their JSON array text, followed by the disclosures and a trailing `~`. `sd_jwt_kb(sd_jwt, header, claims, key)` — appends a `kb+jwt` carrying the `sd_hash` of `sd_jwt`. `digest(input)` — base64url SHA-256, the SD-JWT digest. `jwe(header, payload, recipient)` — compact JWE for a P-256 key by ECDH-ES direct key agreement, as the SDK's `JweEncryptor` builds it; `header` gives `kid`, `enc` and the raw `apu` / `apv`. `x509(spec, key, issuer)` (feature `x509`) — X.509 certificate (PEM) for a P-256 key, self-signed or issued by a CA certificate (PEM) and its key; `spec` is JSON (subject pairs, SANs, dates, CA flag, usages, authority key identifier); the subject keeps the given order, a field or value it cannot apply panics, and the serial number is random. `mdoc(spec, issuer, device)` — mso_mdoc DeviceResponse (base64url CBOR) for one document: tag-24 issuer-signed items with fresh random salts, an MSO with SHA-256 digests and `device`'s EC2 COSE_Key, issuerAuth signed by the DS key with the DS certificate (PEM) as `x5chain`, and a detached device signature over the OID4VP 1.0 SessionTranscript of the spec's `client_id`, `nonce` and optional `response_uri`; `spec` is a typed `serde` struct with `deny_unknown_fields` (doc type, name spaces with string / integer / boolean element values, validity dates, `client_id`, `nonce`), and an unknown or missing field or another value type panics. |

## Key types / traits
- `Keys` — one key per role; every fixture in a process signs with the same keys, so a token and the JWKS or
  `did:key` that verifies it always agree. A field is a `LazyLock<JWK>`, so a generic call such as
  `serde_json::to_value` needs `&*keys().authz`.
- `ssi::JWK` (re-exported as `test_fixtures::JWK`) — the only key type; `JWK::to_public()` is what `jwks` publishes.

## Dependencies
- Depends on: `ssi` (P-256 generation, JWS signing, `did:key`), `rsa` (RSA generation, which `ssi` lacks),
  `jsonwebtoken` (HMAC, which `ssi` lacks), `sha2` (SD-JWT digests), `equs-one-core-crypto` with `equs-one-core-standardized-types` and `secrecy` (the JWE builder and ECDH the SDK itself uses), `rcgen` 0.14.10 or later (the first to write `key_usages` without another extension) with its `x509-parser` feature and `p256` (certificates issued for the same P-256 keys that sign JWS; feature `x509`), `ssi`'s COSE re-exports (`ssi::claims::cose::ciborium`, the mdoc CBOR), `serde` with `derive` (the typed certificate spec and JWE header), `serde_json` with `preserve_order` (headers and claims keep the
  order they are written in), `base64`
- Used by: the SDK's `[dev-dependencies]` (unit tests under `src/`, the E2E suite under `tests/`),
  `plugins/askar` (`[dev-dependencies]`, the vault tests), `demos/multi-thread`, `demos/oid4vc/issuer`, and the test builds of the wrappers: `wrappers/nodejs` and `wrappers/uniffi` (feature `test-fixtures`), `wrappers/wasm` (feature `test-utils`, without `x509`)

## Constraints
- Every builder panics on input it cannot apply instead of dropping or rewriting it; the certificate spec and the
  JWE header are typed `serde` structs with `deny_unknown_fields`, and `null` counts as absent. Fixtures are
  test code, so there is no error type.
- `authz` is a fresh RSA key per process with its RFC 7638 JWK thumbprint as `kid`; a call site writes
  `authz.key_id` into its own `RS256` header, and `jwks(&[&keys().authz])` is the JWK Set to serve wherever a
  test serves the realm's JWKS.
- Every `kid` is derived from the generated key (`did_key_url` for `did:key` tokens, the thumbprint for `authz`),
  so it differs per process — a test must not hard-code one.
- RSA-2048 generation is the only slow step: the workspace root sets `opt-level = 3` for `num-bigint-dig`
  under the dev profile (tens of milliseconds instead of seconds), and it runs only when `authz` is first used.
- Signing is deterministic (ES256 uses RFC 6979 nonces, RS256 is PKCS#1 v1.5, HS256 is a MAC), so two calls
  with the same inputs give the same token.
- A disclosure is digested as the exact JSON text given (`sd_jwt_rs` writes `["salt", "name", value]` with a
  space after each comma; hand-made fixtures are compact), so a recorded salt reproduces the recorded `_sd`
  entry. `_sd` is sorted, as `sd_jwt_rs` sorts it, keeps any digests the caller already put in `_sd` (claims
  left undisclosed), and is omitted when there are none.
- `jwe` encrypts under a fresh ephemeral key each call and supports only `ECDH-ES` (the SDK's `JweEncryptor`
  does the same); `apu` / `apv` are given raw and go on the wire base64url-encoded, as one-core writes them.
- Through `equs-one-core-crypto` the crate needs `getrandom`'s `wasm_js` feature on `wasm32`, which the wasm
  wrapper already enables; a standalone `cargo check --target wasm32-unknown-unknown` of the crate does not.
- `x509` certifies the fixture's own P-256 keys, so a certificate's subject key is the key that signs under its
  `x5c` header; CA keys that certify nothing else are `JWK::generate_p256()` at the call site. The feature pulls
  `rcgen` on `ring`, so a wasm build takes the crate with `default-features = false`.
- `mdoc` builds the two OpenID4VP 1.0 handovers one-core verifies for unencrypted responses: with
  `response_uri`, `[null, null, ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, null, response_uri]))]]`;
  without, `[null, null, ["OpenID4VPDCAPIHandover", SHA-256(CBOR([client_id, nonce, null]))]]`. COSE_Sign1 is untagged
  ES256 with `x5chain` (label 33) in the issuerAuth unprotected header. It needs no `x509` feature (it only
  decodes the PEM), so the wasm build has it. The SDK verifier rejects a self-signed DS certificate, so call
  sites issue it from an IACA with `x509`.
- Run with `cargo test -p equs-test-fixtures`; `cargo test` at the workspace root tests the root package only.
  CI runs it in `test-fixtures-test` (GitHub) and `test-fixtures-test-job` (GitLab).
