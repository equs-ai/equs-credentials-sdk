# .github — GitHub Actions CI

GitHub Actions port of the CI half of `.gitlab-ci.yml`. CI only — no
publish/release jobs. `.gitlab-ci.yml` is the running pipeline, so a CI change
belongs in both files.

| Path | Role |
|------|------|
| `workflows/ci.yml` | 17 jobs, triggers, gating, workflow-level env. |
| `actions/setup-rust/` | Caches, `cargo-binstall`, `sccache`. Assumes Rust on `PATH`. |
| `actions/setup-rustup/` | Installs the pinned toolchain, then `setup-rust`. |
| `actions/setup-wasm/` | clang, then `setup-rustup`, then `wasm-pack`. |
| `scripts/binstall-or-build.sh` | GitLab's `binstall_or_build` helper. Invoked via `bash …`, not executable. |

`check-format` and `lint` gate the six build jobs, which gate the six test jobs,
which gate `oid4vc-demo`. `secret-scan` and `dependency-scan` gate nothing.

## Constraints

- Container images are literals: the `env` context is unavailable to
  `jobs.<id>.container.image`. Literals and env vars change together.
- Cache keys embed a content hash — GitHub cache entries are write-once. The
  npm key hashes `package.json`, since no lockfile is tracked.
- Actions are pinned by commit SHA, never by tag.
- `swift-test` runs on a self-hosted macOS runner, no container, 60-minute
  timeout. The wasm jobs run as root and set `RUSTC_WRAPPER: ""`.
- No CodeQL: it needs a paid licence on a private repo. `gitleaks` covers
  secret detection via its MIT CLI, not the EULA-licensed Action.
