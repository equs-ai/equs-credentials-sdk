# .github — GitHub Actions CI

GitHub Actions port of the CI half of `.gitlab-ci.yml`. CI only — no
publish/release jobs. `.gitlab-ci.yml` is the running pipeline, so a CI change
belongs in both files.

Two entry workflows on the same triggers: `ci.yml` is the main flow — release
builds and every test — and `ci-dev-build.yml` carries the debug workspace
build alongside it rather than on the main flow's critical path. Neither
defines jobs directly; both call reusable workflows, so `container`, checkout,
toolchain and caches are written once. Underscore-prefixed files are
`workflow_call` targets, never triggered on their own.

Because jobs run through `workflow_call`, a check is named `<job> / run`, not
`<job>` — branch-protection rules must use the two-part name.

| Path | Role |
|------|------|
| `workflows/ci.yml` | Triggers, gating and the 18 job calls. No steps. |
| `workflows/ci-dev-build.yml` | `build-dev` alone: the debug workspace build, and the only producer of `target-dev-*`. |
| `workflows/_job.yml` | The generic containerised job behind 17 of the 18. Owns `container`, checkout, toolchain, node/java/wasm, caches, disk report, Codecov and artifact upload. |
| `workflows/_swift.yml` | `swift-test`: `macos-15`, the only job that cannot use the container. |
| `actions/setup-rustup/` | Reclaims host disk, installs the pinned toolchain, restores the sccache and npm caches, installs `cargo-binstall` and `sccache`. |
| `actions/cache/` | Named cache presets (`target-*`, `wrapper-*`), selected by the `restore`/`save` string inputs. |
| `gitleaks.toml` | Secret-scan rules: default set minus the two noisy ones. |
| `scripts/binstall-or-build.sh` | GitLab's `binstall_or_build` helper. Invoked via `bash …`, not executable. |

`lint-and-format` gates everything downstream; `build-prod` gates
`nodejs-wrapper` and `askar-rust`. A job depends only on what it actually
restores: `nodejs-wrapper` takes `target-prod`, so it waits on `build-prod`
alone, while `doc-build`, `wasm-wrapper`, `uniffi-wrapper`, `oid4vc-demo` and
`test-with-coverage` restore no sibling output and wait only on the lint gate.
`askar-wrapper` waits on `askar-rust` and on `nodejs-wrapper`, whose napi build
generates the `@equs-ai/equs-credentials-sdk` types the askar wrapper's `tsc`
step imports. Each test job waits on the wrapper it exercises. Demos run
alongside the tests. `secret-scan` and `dependency-scan` gate nothing.

Jobs are declared in execution order: scans, lint, `build-prod`, the Rust
checks, then each wrapper followed by its test, the three askar jobs together,
and the demos last.

A job declares caches by preset name — `restore: target-askar wrapper-nodejs`
— and `actions/cache` picks the matching blocks by `contains()`. Paths and keys
live in that one action, so a key scheme change is a single edit.

Builds hand work forward through the cache rather than repeating it.
`build-prod` saves the root `target/` under a key hashing `Cargo.lock`, and
`build-dev` saves `target-dev-*` from the other workflow — caches are scoped to
the repository, not the workflow, so the dev-profile consumers restore it across
that boundary and fall back through `restore-keys` when it is cold.
`build-prod` compiles only `-p nodejs`: that package's napi release build is the
sole consumer of root `target/release`, and the command mirrors what
`napi build --release` runs so the fingerprints match.
`askar-rust` saves `plugins/askar/target`, which is where the askar napi wrapper
compiles. Wrapper jobs restore those and save their own output under a
`github.sha` key, so a test job restores exactly the artifacts its run built.

## Constraints

- Every Linux job runs in `rust:1.97.0-bookworm`, the image `.gitlab-ci.yml`
  already uses. GitHub hosts no Debian runner, so the image is the only route
  to one. A first container attempt was reverted after five jobs died for want
  of disk. The 8.4 GB they ran out of is simply what the runner leaves free on
  its 72 GB disk — see the same figure under `test-with-coverage` below, which
  predates any container. A container does not shrink it: the writable layer
  sits on the host's `/`. What a container does remove is the ability to delete
  the ~24 GB of preinstalled toolchains, which is why the reclaim is required
  on any setup, and `container.volumes` is the only way to reach them: it
  bind-mounts them under `/host`, where `setup-rustup` empties them. That step
  is gated on Linux, so `swift-test` skips it. The reclaim fails open — with no
  `/host` the glob does not expand and the job proceeds toward the wall — so do
  not drop the volumes from a job that calls `setup-rustup`. `secret-scan` is
  the one Linux job carrying none, since it never calls it and would read
  nothing.
- `test-with-coverage` sets `--security-opt seccomp=unconfined`: tarpaulin
  traces with ptrace, which Docker's default seccomp profile blocks.
- One image for every Linux job, so `target/` caches transfer between them.
  They did not when `rust:` images (rustc under `/usr/local/rustup`) fed
  `node:` ones (rustc under `$HOME/.cargo`): fingerprints differed and a job
  could hit its cache and still rebuild 1597 crates. Node arrives via
  `actions/setup-node` layered on the Rust image, never as a second image.
- Cache keys embed a content hash — GitHub cache entries are write-once. The
  npm key hashes `package.json`, since no lockfile is tracked.
- One sccache entry for the whole workflow, not one per job. Per-job entries
  reached 8.39 GB of the 10 GB repository ceiling and evicted the `target/`
  caches, which cost more than they saved. The npm entry is keyed the same way,
  on content alone, for the same reason.
- Actions are pinned by commit SHA, never by tag.
- The toolchain versions live in the workflow `env:` block and are read through
  `${{ env.RUST_VERSION }}` / `${{ env.NODE_VERSION }}` in step `with:` inputs.
  `jobs.<id>.container.image` cannot read the `env` context, so its tag stays a
  literal and a version bump touches the `env:` block and every `image:` line.
- `swift-test` pins `macos-15`; `macos-latest` now means `macos-26`. macOS
  bills at 10x here, so it is the only non-Ubuntu job. It builds
  `x86_64-apple-ios` into the debug fat library but tests arm64 only:
  `xcodebuild` cannot run an x86_64 simulator on an arm64 host — Xcode 16
  dropped the `arch=` key, and `ARCHS=x86_64` builds a bundle the arm64
  simulator refuses to load. That slice needs a `macos-15-intel` runner.
  `IOS_DESTINATION` selects by UDID because `OS=latest` — what omitting `OS`
  means — takes the newest runtime even when it lacks the device, and
  `iPhone 16` is absent from iOS 26.x. `CARGO_PROFILE_DEV_DEBUG: "0"` holds
  the job to 14 GB; the runner reports 43 GiB free, so no disk cleanup is
  warranted. `make ios-test` runs two passes because the one test still using
  an in-process HTTP server starves when 53 others compete for three cores.
  Measured through the same client under saturation, that server answers in
  13–21s while an out-of-process one answers in 0.003s, against the hardcoded
  30s timeout at `src/reqwest/mod.rs:46`. Nothing is skipped: 53 + 3 = 56, and
  either pass failing fails the job. Ports, `localhost` resolution (2ms), IPv6
  (`::1` refused in 0.000s), disk, and tokio worker count were each ruled out
  by measurement — do not re-litigate them. The client is not at fault, and a
  successful `connect` proves only that the kernel accepted from the listen
  backlog, not that the server thread is running. The wasm jobs set
  `RUSTC_WRAPPER: ""`.
- Every job sets `timeout-minutes: 30`, except `swift-test` at 60 for its
  three cold iOS target builds: a hung job otherwise bills six hours.
- Jobs sharing a `target/` cache pin `CARGO_PROFILE_DEV_DEBUG: "0"`, which
  keeps the cache under the 10 GB repo limit and keeps cargo fingerprints
  matching across them. `test-with-coverage` sets `line-tables-only` instead: tarpaulin
  maps addresses to lines through DWARF line tables, and a full-debug build
  overruns the 8.4 GB the runner leaves free — the linker dies on SIGBUS, not
  ENOSPC.
- The wrapper release builds run nowhere else — the demos consume `build:debug`
  and `build:dev`, and the napi debug build compiles a different feature set.
- No CodeQL. `gitleaks` covers secret detection via its MIT CLI, not the
  EULA-licensed Action.
- `secret-scan` reads the working tree, not history, so the checkout stays
  shallow. `generic-api-key` and `jwt` are off: they match the crypto test
  vectors this repo is full of, 165 times over. Provider rules are untouched.
- `_job.yml` sets `CARGO_PROFILE_DEV_DEBUG` for every job from one input
  defaulting to `"0"`, rather than repeating it per job. `test-with-coverage`
  is the documented exception, passing `line-tables-only`.
- A `needs` edge exists only where the job restores the upstream job's cache.
  A gate that restores nothing buys serialisation and no warm artifacts.
- `test-with-coverage` writes `Html,Lcov`; the Codecov upload reads `lcov.info`
  and is `fail_ci_if_error: false`, so coverage hosting never gates the merge.
  `--fail-under 70` is the gate. The upload needs the `CODECOV_TOKEN` secret.
- `dependency-scan` reports advisories and does not gate, matching GitLab.
  RUSTSEC-2023-0071 has no patched release, so gating could never go green.
