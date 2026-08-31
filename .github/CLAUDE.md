# .github — GitHub Actions CI

GitHub Actions port of the CI half of `.gitlab-ci.yml`. CI only — no
publish/release jobs. `.gitlab-ci.yml` is the running pipeline, so a CI change
belongs in both files.

| Path | Role |
|------|------|
| `workflows/ci.yml` | 9 jobs, triggers, gating, workflow-level env. |
| `actions/setup-rust/` | Caches, `cargo-binstall`, `sccache`. Assumes Rust on `PATH`. |
| `actions/setup-rustup/` | Installs the pinned toolchain, then `setup-rust`. |
| `actions/setup-wasm/` | clang, then `setup-rustup`, then `wasm-pack`. |
| `gitleaks.toml` | Secret-scan rules: default set minus the two noisy ones. |
| `scripts/binstall-or-build.sh` | GitLab's `binstall_or_build` helper. Invoked via `bash …`, not executable. |

`lint-and-build` gates the five test jobs, which gate `oid4vc-demo`. `secret-scan`
and `dependency-scan` gate nothing.

Jobs are merged by toolchain so one checkout pays the setup once and reuses a
single `target/`: `lint-and-build` runs fmt, clippy, build and doc; `nodejs`
builds the napi wrapper release and debug, then runs the wrapper, shared-suite
and askar tests; `wasm` builds the wrapper release and dev, runs the shared
suite, then builds the demo. The wasm demo's `preinstall` builds the nodejs
demo too, so that has no job of its own.

## Constraints

- Container images are literals: the `env` context is unavailable to
  `jobs.<id>.container.image`. Literals and env vars change together.
- Cache keys embed a content hash — GitHub cache entries are write-once. The
  npm key hashes `package.json`, since no lockfile is tracked.
- Actions are pinned by commit SHA, never by tag.
- `swift-test` runs on a self-hosted macOS runner, no container. The `wasm` job
  runs as root and sets `RUSTC_WRAPPER: ""`.
- Every job sets `timeout-minutes`: a hung job otherwise bills six hours.
- The wrapper release builds run nowhere else — the demos consume `build:debug`
  and `build:dev`, and the napi debug build compiles a different feature set.
- No CodeQL: it needs a paid licence on a private repo. `gitleaks` covers
  secret detection via its MIT CLI, not the EULA-licensed Action.
- `secret-scan` reads the working tree, not history, so the checkout stays
  shallow. `generic-api-key` and `jwt` are off: they match the crypto test
  vectors this repo is full of, 165 times over. Provider rules are untouched.
