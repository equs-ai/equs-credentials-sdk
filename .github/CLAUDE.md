# .github — GitHub Actions CI

GitHub Actions port of the CI half of `.gitlab-ci.yml`. CI only — no
publish/release jobs. `.gitlab-ci.yml` is the running pipeline, so a CI change
belongs in both files.

One workflow, `ci.yml`. It defines no jobs directly: every job calls a
reusable workflow, so `container`, checkout,
toolchain and caches are written once. Underscore-prefixed files are
`workflow_call` targets, never triggered on their own.

Because jobs run through `workflow_call`, a check is named `<job> / run`, not
`<job>` — branch-protection rules must use the two-part name.

| Path | Role |
|------|------|
| `workflows/ci.yml` | Triggers, gating and the 19 job calls. No steps. |
| `workflows/_job.yml` | The generic containerised job behind 18 of the 19. Owns `container`, checkout, toolchain, node/java/wasm, caches, disk report, Codecov and artifact upload. |
| `workflows/_swift.yml` | `swift-test`: `macos-15`. Saves `wrapper-swift`. |
| `workflows/_ios.yml` | `ios-demo`: `macos-15`; restores the XCFramework `swift-test` built. |
| `workflows/_android.yml` | `android-demo`: bare `ubuntu-latest`, SDK from the runner plus the pinned NDK. |
| `actions/setup-rustup/` | Reclaims host disk, installs the pinned toolchain, restores the sccache and npm caches, installs `cargo-binstall` and `sccache`. |
| `actions/cache/` | Named cache presets (`target-*`, `wrapper-*`), selected by the `restore`/`save` string inputs. |
| `gitleaks.toml` | Secret-scan rules: default set minus the two noisy ones. |
| `scripts/binstall-or-build.sh` | GitLab's `binstall_or_build` helper. Invoked via `bash …`, not executable. |

Jobs run in five declared tiers, marked by `# tier N` and ordered in the file:
1 the lint gate plus the two scans, which gate nothing; 2 `build-prod`,
`build-dev` and `doc-build`; 3 the three wrappers, `test-with-coverage`,
`askar-rust` and `oid4vc-demo`; 4 the tests, `askar-wrapper` and `demo-build`;
5 `askar-plugin-nodejs-test`. Every demo in `demos/` is built: `oid4vc-demo`
and `multi-thread-demo` in tier 3, and `demo-build` (wasm), `nodejs-demo-build`,
`android-demo` and `ios-demo` in tier 4. `keycloak` is compose config with
nothing to build. A job names only the specific upstream job it
needs, not the whole tier, so the graph stays as parallel as the data allows.

`swift-test` is deliberately exempt: it sits in tier 4 but waits only on
`uniffi-wrapper`. At 29 minutes it is the longest job, and holding it for the
rest of tier 3 pushed the whole run about 9 minutes later.

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
  to one. Measured on run 35494422506: the runner reports 145 GB with ~110 GB
  free at job start, and the heaviest job (`demo-build`) peaked at 49 GB used.
  An earlier note claimed a container saw only 8.4 GB of a 72 GB disk and that
  ~24 GB of preinstalled toolchains had to be bind-mounted under `/host` and
  deleted to fit. Runners have since grown and that no longer holds, so the
  volumes and the reclaim step are gone. Read the `df` line each job prints
  before reintroducing either.
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
  overran the disk the runner then left free — the linker died on SIGBUS, not
  ENOSPC. Headroom is far larger now; the setting is kept because the 10 GB
  cache ceiling still applies.
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
- `build-dev` carries no `needs`, so it starts alongside `lint-and-format` and
  gates nothing. It is the only producer of `target-dev-*`.
- `android-demo` runs on a bare runner, not the container. The Makefile's
  `android-clang-symlinks` writes `~/.cargo/config.toml`, which cargo ignores
  when `CARGO_HOME` points at the image's `/usr/local/cargo`, losing the NDK
  linker settings. It takes the SDK preinstalled on the runner and adds only
  `ndk;$NDK_VERSION`, and gets 90 minutes: the equivalent GitLab job has hit
  the 60-minute cap.
- `ios-demo` reuses the XCFramework from `swift-test` through `wrapper-swift`
  rather than rebuilding it — the demo's xcodeproj points at
  `wrappers/uniffi/swift/ios/debug`, which is what `ios-generate-xcframework-dev`
  writes and `make ios-test` already produces. It rebuilds only on a cache miss.
  Nothing equivalent exists for Android: `kotlin-test` builds the host target
  only, never the four Android targets or the AAR.
- `multi-thread-demo` greps for `Success`. `start_holders` panics per holder
  but still exits 0, so a plain `cargo run` would pass with every holder failed.
- `cargo tarpaulin` takes `--out` once per format: `-o Html -o Lcov`. A comma
  list is rejected as an invalid value.
- Most `needs` edges carry a cache: the job restores what the upstream job
  saved. Three are ordering only, and deliberately so — `test-with-coverage`
  and `swift-test` restore nothing, and `askar-rust` builds into its own
  `target-askar` rather than anything `build-prod` produced.
- `test-with-coverage` waits on `build-dev` but cannot reuse `target-dev`:
  tarpaulin builds with its own instrumentation and `line-tables-only` debug
  info, so every fingerprint differs from `build-dev`'s `"0"` and cargo
  rebuilds regardless. Restoring that cache would cost a download and save
  nothing.
- `test-with-coverage` writes `Html,Lcov`; the Codecov upload reads `lcov.info`
  and is `fail_ci_if_error: false`, so coverage hosting never gates the merge.
  `--fail-under 70` is the gate. The upload needs the `CODECOV_TOKEN` secret.
- `dependency-scan` reports advisories and does not gate, matching GitLab.
  RUSTSEC-2023-0071 has no patched release, so gating could never go green.
