# JWT Test Fixture Crate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `test-fixtures/` workspace member that mints a valid token of every JWT kind the SDK handles, plus a JWE, signed at test runtime through the SDK's `Signer` trait rather than committed as a static string.

**Architecture:** One builder type per kind, each `Kind::builder(..) → … → .build().await`. Required arguments are that kind's required inputs, so a missing one is a compile error rather than a runtime failure; everything else defaults and is overridable. Signing always goes through a `FixtureKey` — a `LocalKms` key handle plus the `did:key` derived from it — so no builder touches raw key material and a regression in the signing stack fails these fixtures rather than hiding behind a pre-baked string. Where the SDK exposes a public constructor for a kind, the builder calls it; where the kind is built inside a private module, the claim set is assembled here and signed through the same handle.

**Tech Stack:** Cargo workspace member (`equs-test-fixtures`, lib target `test_fixtures`, `publish = false`), `equs-credentials-sdk` with `in-memory`, `base64`, `serde_json`, `ssi`, `snafu`; `tokio` for the suite.

**Spec:** [`docs/superpowers/specs/2026-09-24-jwt-test-fixtures-design.md`](../specs/2026-09-24-jwt-test-fixtures-design.md), approved. It lives on branch `docs/jwt-fixtures-spec` and is not on `main`.

## Global Constraints

- Complexity: ⚠️ Medium.
- Branch: `feature/jwt-test-fixtures`, from `github-equs/main`.
- `publish = false` on the crate, and the SDK's dev-dependency on it carries no `version` key, so `cargo package` strips it and the crates.io release path merged in #13 is untouched. Task 1 proves this before any builder is written.
- Every builder signs through `equs_sdk::crypto::Signer`, backed by `equs_sdk::inmem::kms::LocalKms`. No builder takes, holds or emits raw key material.
- Positive fixtures only. Negative and malformed-token generation stays in the error-path tests that already own it.
- No new external package enters the dependency graph. `base64`, `ssi`, `serde_json`, `snafu`, `async-trait`, `time` and `tokio` are all already resolved in `Cargo.lock` for the SDK (AI_CONSTITUTION §5.6).
- No explanatory comment blocks in CI config — rationale lives in `.github/CLAUDE.md` and `test-fixtures/CLAUDE.md`, not in the YAML.
- A CI change belongs in both `.gitlab-ci.yml` and `.github/workflows/ci.yml` (`.github/CLAUDE.md`).
- The toolchain is a rustup *directory* override on the main checkout and does not follow into a worktree: prefix commands with `RUSTUP_TOOLCHAIN=1.97`.
- `cargo clippy` must carry `--exclude wasm`; the wasm wrapper's ~66 `E0277`s are pre-existing.
- Migration of the SDK's existing `#[cfg(test)]` constants is out of scope. They stay where they are and move to the builders opportunistically.

## File Structure

| Path | Responsibility |
|------|----------------|
| `test-fixtures/Cargo.toml` | Package manifest; `publish = false`, `delegate-sd-jwt` forwarding feature |
| `test-fixtures/src/lib.rs` | Crate root; module declarations and the `equs_sdk` re-export the SDK's unit tests use |
| `test-fixtures/src/error.rs` | `Error` / `Result` |
| `test-fixtures/src/keys.rs` | `FixtureKey` over all four `KeyType`s |
| `test-fixtures/src/claims.rs` | Shared claim defaults and clock helpers |
| `test-fixtures/src/jws.rs` | Compact JWS assembly over `crypto::Signer` |
| `test-fixtures/src/http.rs` | `StaticHttpClient` |
| `test-fixtures/src/{pop,sd_jwt_vc,kb_jwt,dsd_jwt,status_list,request_object,id_token,vp_token,jwe}.rs` | One builder each |
| `test-fixtures/tests/round_trip.rs` | Round-trip + failure case per publicly verifiable kind |
| `test-fixtures/tests/delegation.rs` | The same for `dsd_jwt`, behind the feature |
| `test-fixtures/CLAUDE.md` | Directory context file. New |
| `Cargo.toml` | Workspace member and the dev-dependency back-edge |
| `src/vc/pop/jwt_pop.rs` | Round-trip unit tests for the PoP builder |
| `src/vc/oid4vp/verifier.rs` | Round-trip unit tests for the `id_token` builder |
| `src/vc/oid4vp/holder.rs` | Round-trip unit tests for the request-object builder |
| `.github/workflows/ci.yml`, `.gitlab-ci.yml` | The `test-fixtures-test` job |
| `.github/CLAUDE.md`, `claude/tests.md`, `context.claude.md` | Context system |

---

### Task 1: Prove the dev-dependency cycle

**Files:**
- Create: `test-fixtures/Cargo.toml`, `test-fixtures/src/lib.rs`
- Modify: `Cargo.toml` (workspace member, `[dev-dependencies]`)
- Test: a unit test in `src/lib.rs` calling the fixture crate, plus `cargo package`

**Interfaces:**
- Produces: package `equs-test-fixtures`, lib target `test_fixtures`, at `test-fixtures/`. Every later task depends on this answer.

This is the one assumption in the spec carrying risk, and nothing else is written until it is settled. If the cycle misbehaves, the fallback is that the crate serves `tests/` integration tests only and `src/` unit tests keep their existing constants.

- [x] **Step 1: Scaffold the crate with one trivial function and wire both edges**

`test-fixtures/Cargo.toml` declares `publish = false` and `equs-credentials-sdk = { path = "..", features = ["in-memory"] }`; the root `Cargo.toml` gains `"test-fixtures"` to `[workspace] members` and `equs-test-fixtures = { path = "./test-fixtures" }` to `[dev-dependencies]`.

- [x] **Step 2: Validation test — a `src/` unit test reaches the fixture crate**

Run: `RUSTUP_TOOLCHAIN=1.97 cargo test --all-features -p equs-credentials-sdk --lib`
Expected: PASS. Cargo compiles `equs-credentials-sdk`, then `equs-test-fixtures`, then the SDK's test binary linking it.

- [x] **Step 3: Validation test — publishing is unaffected**

Run: `RUSTUP_TOOLCHAIN=1.97 cargo package --allow-dirty --no-verify -p equs-credentials-sdk`
Expected: PASS, and `equs-test-fixtures` does not appear in the packaged `Cargo.toml`'s `[dev-dependencies]`.

**Verdict: the cycle works, with one constraint that shapes Task 4.** Building the SDK's test target compiles `equs_sdk` twice — once as the library `equs-test-fixtures` links, once as the `cfg(test)` crate under test — and the two sets of types do not unify. A `src/` unit test cannot hand a `crate::inmem::kms::LocalKms` to a builder. The crate therefore re-exports `pub use equs_sdk;`, and a unit test constructs a builder's inputs through `test_fixtures::equs_sdk::…` and carries only the token `String` back across the boundary. Tokens are strings, so this costs nothing at the call site.

---

### Task 2: Keys, claims, signing and the HTTP stub

**Files:**
- Create: `test-fixtures/src/{error,keys,claims,jws,http}.rs`
- Modify: `test-fixtures/src/lib.rs`
- Test: `test-fixtures/tests/round_trip.rs::keys_cover_every_key_type`

**Interfaces:**
- Consumes: Task 1's manifest.
- Produces: `FixtureKey { kid, did, did_url, handle }` with `create(&LocalKms, KeyType)` and `create_default`; `sign_compact(&FixtureKey, typ, &Value)`; `StaticHttpClient`. Every builder in Tasks 3–5 consumes these.

`src/utils/test_utils.rs` is `#[cfg(test)] pub(crate)` inside a private `mod utils`, so `create_did_and_key_metadata_by_key_type` is not reachable from outside the crate. `keys.rs` rebuilds it from the public API — `DIDKey::generate` plus `UniversalResolver::resolve_into_any_verification_method` — which is what `tests/utils/helpers/mod.rs` already does.

- [x] **Step 1: Write `FixtureKey`, the claim defaults, the JWS assembler and the HTTP stub**

- [x] **Step 2: Validation test — every `KeyType` mints a usable key**

Run: `RUSTUP_TOOLCHAIN=1.97 cargo test --all-features -p equs-test-fixtures keys_cover_every_key_type`
Expected: PASS for `Ed25519`, `P256`, `K256` and `Bls12381` — each yields a `did:key` whose verification method URL belongs to it.

---

### Task 3: The builders with a public SDK constructor

**Files:**
- Create: `test-fixtures/src/{sd_jwt_vc,kb_jwt,status_list,vp_token,jwe}.rs`
- Test: `test-fixtures/tests/round_trip.rs`

**Interfaces:**
- Consumes: `FixtureKey`, `StaticHttpClient`.
- Produces: `SdJwtVc`, `KbJwt`, `StatusListToken`, `VpToken`, `Jwe`. `VpToken` composes `KbJwt`; Task 5 composes `SdJwtVc`.

Each of these has a reachable SDK constructor, so the builder calls it rather than assembling JOSE by hand: `VCFormatsSdJwtAPI::create_vc`, `vc::core::HolderService::create_presentation`, `StatusListJwt::create_status_list`, `vc::oid4vp::jwe::JweEncryptor::encrypt`. A KB-JWT's `sd_hash` digests the exact credential and disclosure set it ships with, so it cannot be built independently of them — hence the holder service rather than the format layer, whose `VPMetadata` is not re-exported.

TDD order: the round-trip test for a builder is written before the builder.

- [x] **Step 1: Write the round-trip and failure tests, then each builder**

- [x] **Step 2: Validation test — every token satisfies the SDK's own verifier**

Run: `RUSTUP_TOOLCHAIN=1.97 cargo test --all-features -p equs-test-fixtures --test round_trip`
Expected: PASS. Per kind, one round-trip and one failure the verifier actually rejects:

| Kind | Verifier | Failure case |
|---|---|---|
| SD-JWT VC | `VCFormatsSdJwtAPI::verify_vc` | `verify_signature` under an unrelated key |
| KB-JWT | `VCFormatsSdJwtAPI::verify_vp` | a `HolderBinder` carrying another nonce |
| `vp_token` | `vc::core::VerifierService::verify_presentation` | a `HolderBinder` carrying another nonce |
| Status list | `StatusListJwt::get_vc_status` | an index outside the list |
| JWE | `LocalKms::decrypt` | decryption under an unrelated key |

A KB-JWT carries no `exp`, so "expired" is not a failure this verifier can produce; a status list token carries no `exp` either, and its verifier checks neither expiry nor audience. The failure case per kind is the one that kind's verifier really enforces.

---

### Task 4: The builders whose SDK verifier is private

**Files:**
- Create: `test-fixtures/src/{pop,request_object,id_token}.rs`
- Modify: `src/vc/pop/jwt_pop.rs`, `src/vc/oid4vp/verifier.rs`, `src/vc/oid4vp/holder.rs`
- Test: the three `#[cfg(test)] mod tests` blocks above, plus claim assertions in `tests/round_trip.rs`

**Interfaces:**
- Consumes: `FixtureKey`, `sign_compact`, and Task 1's `test_fixtures::equs_sdk` re-export.
- Produces: `ProofOfPossession`, `RequestObject`, `IdToken`.

`vc::pop` is a private module and `vc::formats` is `pub(crate)`; the OID4VP request object and `id_token` are assembled inside `vc::oid4vp` with no public constructor. So these three claim sets are built here, and their verifiers are reachable only from inside the SDK. Their round-trips are therefore SDK unit tests — which is what the dev-dependency cycle is for.

- [x] **Step 1: Write the builders, matching each kind's header and claim set**

`openid4vci-proof+jwt` with `aud`/`exp` required and `iss`/`nbf`/`nonce` omitted unless set; `oauth-authz-req+jwt` with a `kid` whose DID matches `client_id`; `typ: JWT` with `iss == sub ==` the signing key's DID.

- [x] **Step 2: Validation test — each token satisfies the SDK's private verifier**

Run: `RUSTUP_TOOLCHAIN=1.97 cargo test --all-features -p equs-credentials-sdk --lib fixture`
Expected: PASS, 6 tests:

| Kind | Verifier | Failure case |
|---|---|---|
| PoP | `JwtProofOfPossession::verify` | a wrong `aud` → `pop::Error::Verification` |
| Request object | `RequestVerifier::decentralized_identifier` | a `client_id` naming another DID → "do not match" |
| `id_token` | `VerifierService::validate_id_token` | a past `exp` → "id token is expired" |

---

### Task 5: The delegate SD-JWT builder

**Files:**
- Create: `test-fixtures/src/dsd_jwt.rs`, `test-fixtures/tests/delegation.rs`
- Modify: `test-fixtures/Cargo.toml` (`delegate-sd-jwt` feature), `test-fixtures/src/lib.rs`

**Interfaces:**
- Consumes: `SdJwtVc` for the credential being delegated over.
- Produces: `DsdJwt`, behind `delegate-sd-jwt`.

The feature forwards to `equs-credentials-sdk/delegate-sd-jwt`; a local toggle would compile and then fail at runtime, because the chain machinery lives behind the SDK's feature.

- [x] **Step 1: Write the round-trip test, then the builder**

- [x] **Step 2: Validation test — the grant satisfies the SDK's delegation verifier**

Run: `RUSTUP_TOOLCHAIN=1.97 cargo test --all-features -p equs-test-fixtures --test delegation`
Expected: PASS, 2 tests. `vc::core::VerifierService::verify_delegation` accepts the grant and returns both `issued_vc` and `delegations`; a `HolderBinder` carrying another nonce is rejected.
With the feature off, the file compiles to nothing.

---

### Task 6: CI

**Files:**
- Modify: `.github/workflows/ci.yml`, `.gitlab-ci.yml`
- Test: `actionlint`

**Interfaces:**
- Produces: job `test-fixtures-test` (GitHub, tier 2, `needs: [fmt]`) and `test-fixtures-test-job` (GitLab, `test` stage).

`cargo tarpaulin` at the workspace root inherits cargo's default package selection — the root package only — so a new workspace member never runs in CI without its own job. This is the same gap `common-macros-test` was added to close, and the job mirrors it. `--all-features` is passed so the `delegate-sd-jwt` suite runs.

`test-fixtures/*` also joins tarpaulin's `--exclude-files` list, beside `demos/*` and `wrappers/*`. The crate is a workspace path dependency, so tarpaulin counts its lines while running only the root package's tests — which reach three of the nine builders. The rest is covered by `test-fixtures-test`, which tarpaulin never runs, so leaving it in would drag the `--fail-under 70` gate for nothing.

- [x] **Step 1: Add both jobs, and the tarpaulin exclusion**

- [x] **Step 2: Validation test — the workflow is still valid**

Run: `actionlint .github/workflows/ci.yml`
Expected: no output, exit 0.

---

### Task 7: Context system

**Files:**
- Create: `test-fixtures/CLAUDE.md`
- Modify: `claude/tests.md`, `context.claude.md`, `.github/CLAUDE.md`

**Interfaces:**
- Consumes: the finished layout from Tasks 1–6.

- [x] **Step 1: Write the directory context file**

Files table, the builder-per-kind shape, the dependency cycle and its type-unification constraint, and the `cargo test -p` command the crate needs.

- [x] **Step 2: Follow the chain upward**

`claude/tests.md` gains the sub-area row, the cycle, and the "no committed token strings" rule. `context.claude.md` gains the directory in the layout tree and the forwarded feature in the cross-cutting constraints. `.github/CLAUDE.md`'s job count goes 27 → 28 and its "`common-macros-test` is the only job that runs `cargo test`" note becomes false and is rewritten.

None of the `claude/*.md` files carry a "Last updated" line, so none is added — one file with a field the other eight lack would be the stale thing.

---

### Task 8: Full validation

- [x] `RUSTUP_TOOLCHAIN=1.97 cargo fmt --all`
- [x] `RUSTUP_TOOLCHAIN=1.97 cargo build --all-features --workspace --exclude wasm`
- [x] `RUSTUP_TOOLCHAIN=1.97 cargo test --all-features`
- [x] `RUSTUP_TOOLCHAIN=1.97 cargo test --all-features -p equs-test-fixtures`
- [x] `RUSTUP_TOOLCHAIN=1.97 cargo clippy --workspace --all-targets --all-features --exclude wasm -- -Dwarnings`
- [x] `RUSTUP_TOOLCHAIN=1.97 cargo package --allow-dirty --no-verify -p equs-credentials-sdk`
