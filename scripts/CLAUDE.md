# scripts/

Scripts called by the release pipelines, plus the embedded-token security gate.
GitHub Actions has its own set under `.github/scripts/`.

| File | Purpose |
|------|---------|
| `release_manifest.sh` | Renders `release-manifest.yaml` for one crate's release. |
| `npm_release_manifest.sh` | Renders `release-manifest.yaml` for one npm release. |
| `maven_release_manifest.sh` | Renders `release-manifest.yaml` for one Maven release. |
| `file_release_manifest.sh` | Renders `release-manifest.yaml` for a release shipped as plain files. |
| `scan-embedded-tokens.py` | Walks `git ls-files`, flags committed JWT/JWE strings and private key material, exits non-zero on a `--fail-on` path hit. |
| `test_scan_embedded_tokens.py` | `unittest` regression tests for the scanner's detectors — run with `python3 scripts/test_scan_embedded_tokens.py` or `python3 -m unittest discover -s scripts -p "test_*.py"`. |

## release_manifest.sh

`release_manifest.sh <crate> [output]` — one crate per run, because each crate
releases on its own tag. The SDK's manifest is rendered by
`.github/workflows/publish-crate.yml` (called by `release.yml`) and by `release_manifest_job` in the
`manifest` stage; the macro crate's by
`.github/workflows/publish-common-macros.yml`.

Both workflows render with `if: always()`, so a failed publish still produces a
manifest, and a follow-up job uploads it to that tag's release as an asset (for
the SDK, `release.yml`'s `release` job, as `release-manifest-crate.yaml` beside
the three npm manifests, and only once every package published) —
build artifacts expire after 90 days, release assets do not. The release is
created if the tag has none, and the notes are never touched. The `manifest`
stage keeps the file as a build artifact only.

Every field comes from the checkout — no registry calls. `commit` and `tag` come
from the release build, `repo` from `Cargo.toml`'s `repository` URL (not
`CI_PROJECT_PATH`, whose namespace differs from the GitHub path the crate
advertises), and the version from `cargo metadata --no-deps`.

The digest is the sha256 of the `.crate` tarball `cargo package --locked
--no-verify` builds at this commit. Cargo stamps `.cargo_vcs_info.json` with the
commit sha, so a crate packaged at another commit hashes differently even when
its sources are identical — which is why each crate's manifest has to be
rendered by the job that publishes it. Verification is skipped because it only
rebuilds the crate; it does not change the tarball.

- `RELEASE_VERSION` sets the `release:` field, defaulting to `CI_COMMIT_TAG`.
  The macro crate's tag is `common-macros/vX.Y.Z`, so its workflow passes the
  bare version and the raw tag stays in `tag:`.
- A crate that fails to package is emitted with `digest: null` and a warning
  rather than failing the job. `cargo package` rejects a path dependency that
  carries no version requirement, so the root package's dependency on
  `equs-common-macros` has to keep its `version` field.
- `RELEASE_MANIFEST_PACKAGE_FLAGS` appends flags to `cargo package`, e.g.
  `--allow-dirty --offline` for a local run outside CI.

## npm_release_manifest.sh

`npm_release_manifest.sh <component> <output> <tarball-dir> <package>...` —
same schema as `release_manifest.sh`, one entry per package. Called by the
`manifest` job of `.github/workflows/publish-nodejs.yml` and `publish-askar-nodejs.yml`
(each wrapper and its three platform packages) and `publish-wasm.yml`.

The digest is the sha256 of the tarball the publish job packed and passed to
`npm publish`, found in `<tarball-dir>` by npm's file name
(`equs-ai-<name>-<version>.tgz`). The version is read from the tarball's
`package.json`. A missing tarball is emitted with `digest: null` and a warning.
`RELEASE_VERSION` sets `release:` — the tags are `nodejs/vX.Y.Z`,
`askar-nodejs/vX.Y.Z`, `wasm/vX.Y.Z` or the SDK's `vX.Y.Z`, so the workflows pass
the bare version.

## maven_release_manifest.sh

`maven_release_manifest.sh <group:artifact> <output> <file>` — same schema as
`release_manifest.sh`, one entry. Called by the `manifest` job of
`.github/workflows/publish-android.yml` with the AAR it uploaded; the digest is
that file's sha256, and a missing file is emitted with `digest: null`.
`RELEASE_VERSION` sets `release:`, since the tag is `android/vX.Y.Z` or `vX.Y.Z`.

## file_release_manifest.sh

`file_release_manifest.sh <component> <output> <file>...` — same schema, one
entry per file, named by its basename. Called by the `manifest` job of
`.github/workflows/publish-ios.yml` with the iOS XCFramework zip. The digest is the
sha256 of the file the job attaches to the release; a missing file is emitted
with `digest: null` and a warning. `RELEASE_VERSION` sets `release:` and every
entry's `version:`.

## scan-embedded-tokens.py

`scan-embedded-tokens.py [--fail-on PATH…]` — no arguments just reports; one or
more `--fail-on` paths make it a gate that exits `1` if any token or private
key falls under them. Python 3 standard library only, no new dependency. Runs
in CI on `rust:${RUST_VERSION}-bookworm` (needs `git` on `PATH`, which
`python:3-slim` doesn't have); if `git` is missing, `git_tracked_files()`
raises `ScanEnvironmentError` and `main()` exits `3` — distinct from `1`
("tokens found") and `2` (argparse usage error) — so a broken CI image never
reads as a security finding.

It matches `eyJ…` runs shaped like a compact JWS/JWE, base64url-decodes the
first segment and requires an `alg` or `enc` member before counting it as a
real token (not just base64-ish text), then classifies it by its `exp` claim
(live / expired / no-exp / encrypted). Separately it flags a JSON object
carrying both `kty` and `d` (a private JWK) and any PEM `-----BEGIN … PRIVATE
KEY-----` block. A Rust `\`-continued string literal is collapsed before
matching, so a token wrapped across physical lines is not missed.

Before matching, `normalize()` collapses three ways a token or key gets split
or obscured across the raw bytes of a source file: a Rust backslash-newline
continuation, a `"..." + "..."`-style string concatenation (the normal way to
wrap a long string in JS/TS/Kotlin/Swift), and a `\"`-escaped JSON literal
(how a JWK ends up embedded inside an ordinary, non-raw string). Each of
those was a real blind spot caught in review, not a hypothetical — see the
script's own module docstring for what it still cannot see (JWS JSON
Serialization, computed/interpolated strings, git history).

`test_scan_embedded_tokens.py` pins all three blind-spot fixes plus the core
detectors (`find_tokens`, `find_private_jwks`, `find_pem_private_keys`,
`under_any`) down as regression tests; run it before touching `normalize()`,
`TOKEN_RE` or the two key detectors.

See `claude/tests.md` for the current clean/dirty state of each part of the
tree.
