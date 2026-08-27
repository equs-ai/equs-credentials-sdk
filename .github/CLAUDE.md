# .github — GitHub Actions CI

GitHub Actions port of the CI half of `.gitlab-ci.yml`. **CI only** — the
publish/release jobs are deliberately absent.

Both pipelines are live simultaneously. The repository still hosts on GitLab,
so these workflows are dormant until the migration (ASI-6822 / W4). Changes to
CI must be made in **both** files until the cutover.

| Path | Role |
|------|------|
| `workflows/ci.yml` | All 17 jobs, triggers, gating, workflow-level env. |
| `actions/setup-rust/` | Caches + `cargo-binstall` + `sccache`. Assumes Rust on `PATH`. ← `.rust_job_configs` |
| `actions/setup-rustup/` | Installs the pinned toolchain, then `setup-rust`. ← `.nodejs_job_configs`, `.swift_job_configs` |
| `actions/setup-wasm/` | clang → `setup-rustup` → `wasm-pack`. ← the inline wasm `before_script` |
| `scripts/binstall-or-build.sh` | Standalone script form of GitLab's `binstall_or_build` helper. Invoked via `bash …` — deliberately not executable. |

## Constraints

- **Container image strings are hardcoded.** The `env` context is unavailable
  to `jobs.<id>.container.image`; `${{ env.RUST_VERSION }}` there resolves to
  an empty string. Update the literals and the env vars together.
- **Cache keys must embed a content hash.** GitHub cache entries are
  write-once, so a static key populates once and then never refreshes.
- **Actions are pinned by commit SHA**, never by tag.
- **No CodeQL.** Code scanning on a private repo needs a paid GitHub Code
  Security licence. Revisit when the repo goes public (W4.4).

Design rationale, cost analysis, and the full list of deviations from the
GitLab pipeline: `docs/superpowers/specs/2026-08-27-github-actions-ci-design.md`.
