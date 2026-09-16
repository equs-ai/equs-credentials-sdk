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
| `gitleaks.toml` | Secret-scan config. |
| `scripts/binstall-or-build.sh` | GitLab's `binstall_or_build` helper. Invoked via `bash …`, not executable. |

`lint-and-format` gates `build-dev` and `build-prod`; `build-prod` gates
`askar-rust`. The four wrapper jobs wait on both builds, `askar-wrapper` on
`askar-rust` and on `nodejs-wrapper`, whose napi build generates the
`@equs-ai/equs-credentials-sdk` types the askar wrapper's `tsc` step imports.
Each test job waits on the wrapper it exercises. Demos run alongside the tests.
`secret-scan` and `dependency-scan` gate nothing.

Builds hand work forward through the cache rather than repeating it. `build-dev`
and `build-prod` each save the root `target/` under a key hashing `Cargo.lock`.
`build-prod` compiles only `-p nodejs`: that package's napi release build is the
sole consumer of root `target/release`, and the command mirrors what
`napi build --release` runs so the fingerprints match.
`askar-rust` saves `plugins/askar/target`, which is where the askar napi wrapper
compiles. Wrapper jobs restore those and save their own output under a
`github.sha` key, so a test job restores exactly the artifacts its run built.
`nodejs-wrapper` restores both roots: `npm run build` is a release build and
`npm run build:debug` a dev one. `demo-build` also restores
`plugins/askar/target`, since its preinstall chain rebuilds the askar napi
crate there with sccache off.

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
  npm key hashes `package.json`, since no lockfile is tracked, and is shared
  across jobs: the hash is identical everywhere, so a per-job qualifier bought
  19 copies of one 120 MB entry against the 10 GB ceiling.
- One sccache entry per runner OS and arch, not one per job. Per-job entries
  reached 8.39 GB of the 10 GB repository ceiling and evicted the `target/`
  caches, which cost more than they saved. The qualifier stops the macOS job
  sharing a key whose objects Linux cannot reuse.
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
  ENOSPC. That profile is why it restores no `target/` cache, and a dedicated
  one would be a fourth multi-GB family against the ceiling above, so it gates
  on `lint-and-format` rather than waiting on `build-dev` for nothing.
- The wrapper release builds run nowhere else — the demos consume `build:debug`
  and `build:dev`, and the napi debug build compiles a different feature set.
- No CodeQL. `gitleaks` covers secret detection via its MIT CLI, not the
  EULA-licensed Action.
- `secret-scan` reads the working tree, not history, so the checkout stays
  shallow. `generic-api-key` and `jwt` stay enabled and are allowlisted by
  value shape, not by path: did:key multibase identifiers, compact JWTs and
  W3C `…Key20xx` method-type names. Those three shapes are every hit in the
  tree, and matching on them leaves both rules live in every file, so a new
  fixture needs no config change. Provider rules are untouched.
- `dependency-scan` reports advisories and does not gate, matching GitLab.
  RUSTSEC-2023-0071 has no patched release, so gating could never go green, and
  a missing report warns rather than fails — `cargo audit --json` writes
  nothing when the advisory DB is unreachable.
