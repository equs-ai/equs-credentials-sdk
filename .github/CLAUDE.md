# .github — GitHub Actions CI

GitHub Actions port of the CI half of `.gitlab-ci.yml`. CI only — no
publish/release jobs. `.gitlab-ci.yml` is the running pipeline, so a CI change
belongs in both files.

| Path | Role |
|------|------|
| `workflows/ci.yml` | 19 jobs, triggers, gating, workflow-level env. |
| `actions/setup-rust/` | Caches, `cargo-binstall`, `sccache`. Assumes Rust on `PATH`. |
| `actions/setup-rustup/` | Installs the pinned toolchain, then `setup-rust`. |
| `actions/setup-wasm/` | clang, then `setup-rustup`, then `wasm-pack`. |
| `gitleaks.toml` | Secret-scan rules: default set minus the two noisy ones. |
| `scripts/binstall-or-build.sh` | GitLab's `binstall_or_build` helper. Invoked via `bash …`, not executable. |

`lint-and-format` gates `build-dev` and `build-prod`; `build-prod` gates
`askar-rust`. The four wrapper jobs wait on both builds, `askar-wrapper` on
`askar-rust` and on `nodejs-wrapper`, whose napi build generates the
`@equs/equs-sdk` types the askar wrapper's `tsc` step imports. Each test job waits on the wrapper it exercises. Demos run
alongside the tests. `secret-scan` and `dependency-scan` gate nothing.

Builds hand work forward through the cache rather than repeating it. `build-dev`
and `build-prod` each save the root `target/` under a key hashing `Cargo.lock`.
`build-prod` compiles only `-p nodejs`: that package's napi release build is the
sole consumer of root `target/release`, and the command mirrors what
`napi build --release` runs so the fingerprints match.
`askar-rust` saves `plugins/askar/target`, which is where the askar napi wrapper
compiles. Wrapper jobs restore those and save their own output under a
`github.sha` key, so a test job restores exactly the artifacts its run built.

## Constraints

- Jobs run on bare runners, not containers. A container gets 8.4 GB of the
  runner's 72 GB, and the ~24 GB of preinstalled toolchains that would free it
  sit on the host, out of reach from inside. Five jobs died on that before the
  move; `setup-rustup` now deletes those toolchains on every Linux job. Running
  outside Docker also drops the `seccomp`/`SYS_PTRACE` options tarpaulin needed
  purely to get past Docker's own seccomp profile.
- One toolchain layout everywhere, so `target/` caches transfer between jobs.
  They did not when `rust:` images (rustc under `/usr/local/rustup`) fed
  `node:` ones (rustc under `$HOME/.cargo`): fingerprints differed and a job
  could hit its cache and still rebuild 1597 crates.
- Cache keys embed a content hash — GitHub cache entries are write-once. The
  npm key hashes `package.json`, since no lockfile is tracked.
- One sccache entry for the whole workflow, not one per job. Per-job entries
  reached 8.39 GB of the 10 GB repository ceiling and evicted the `target/`
  caches, which cost more than they saved.
- Actions are pinned by commit SHA, never by tag.
- `swift-test` pins `macos-15`; `macos-latest` now means `macos-26`. macOS
  bills at 10x here, so it is the only non-Ubuntu job. It builds
  `x86_64-apple-ios` into the debug fat library but tests arm64 only:
  `xcodebuild` cannot run an x86_64 simulator on an arm64 host — Xcode 16
  dropped the `arch=` key, and `ARCHS=x86_64` builds a bundle the arm64
  simulator refuses to load. That slice needs a `macos-15-intel` runner.
  `IOS_DESTINATION` selects by UDID because `OS=latest` — what omitting `OS`
  means — takes the newest runtime even when it lacks the device, and
  `iPhone 16` is absent from iOS 26.x. `CARGO_PROFILE_DEV_DEBUG: "0"` holds
  the job to 14 GB against ~14 GB per target; runner disk is unmeasured, hence
  `df -h /`. `TEST_RUNNER_TOKIO_WORKER_THREADS` is the prefix xcodebuild
  forwards into the simulator, stripped; plain env vars never reach the test
  process. UniFFI sizes its global tokio runtime to CPU count, and 3 workers
  is too few for the suite's concurrent async calls — an HTTP request stalls
  against a listening server. Reproduced locally: 2 and 3 workers fail, 4, 8
  and 16 pass, so 8 carries margin. The wasm jobs set `RUSTC_WRAPPER: ""`.
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
- No CodeQL: it needs a paid licence on a private repo. `gitleaks` covers
  secret detection via its MIT CLI, not the EULA-licensed Action.
- `secret-scan` reads the working tree, not history, so the checkout stays
  shallow. `generic-api-key` and `jwt` are off: they match the crypto test
  vectors this repo is full of, 165 times over. Provider rules are untouched.
- `dependency-scan` reports advisories and does not gate, matching GitLab.
  RUSTSEC-2023-0071 has no patched release, so gating could never go green.
