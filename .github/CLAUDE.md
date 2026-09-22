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
| `workflows/ci.yml` | Triggers, gating and the 25 job calls. No steps. |
| `workflows/_job.yml` | The generic containerised job behind 21 of the 25. Owns `container`, checkout, toolchain, node/java/wasm, caches, disk report and artifact upload. |
| `workflows/_macos.yml` | The generic `macos-15` job behind `ios-xcframework`, `swift-test` and `ios-demo`. |
| `workflows/_android.yml` | `android-demo`: bare `ubuntu-latest`, SDK from the runner plus the pinned NDK. |
| `actions/setup-rustup/` | Reclaims host disk, installs the pinned toolchain, restores the sccache and npm caches, installs `cargo-binstall` and `sccache`. |
| `actions/cache/` | Named cache presets (`target-*`, `wrapper-*`), selected by the `restore`/`save` string inputs. |
| `gitleaks.toml` | Secret-scan config. |
| `scripts/install-gitleaks.sh` | Pinned gitleaks download with its SHA256; prints the binary path. |
| `scripts/coverage-badge.sh` | Writes the coverage SVG to the `badges` branch. Runs only on `main`. |
| `scripts/binstall-or-build.sh` | Installs a `cargo-X` subcommand, falling back to a source build. Derives the check from the crate name, so it takes one argument where GitLab's `binstall_or_build` takes two. |

Jobs run in five declared tiers, marked by `# tier N` and ordered in the file:
1 `fmt` plus the two scans, which gate nothing; 2 `clippy`, `build-prod`,
`build-dev`, `doc-build` and `ios-xcframework`; 3 the three wrappers, `test-with-coverage`,
`askar-rust` and `oid4vc-demo`; 4 the tests, `askar-wrapper` and `demo-build`;
5 `askar-plugin-nodejs-test`. Every demo in `demos/` is built: `oid4vc-demo`
and `multi-thread-demo` in tier 3, and `demo-build` (wasm), `nodejs-demo-build`,
`android-demo` and `ios-demo` in tier 4. `keycloak` is compose config with
nothing to build. A job names only the specific upstream job it
needs, not the whole tier, so the graph stays as parallel as the data allows.

`fmt` is the gate, not clippy: `cargo fmt --check` takes seconds where clippy
takes minutes, and every job used to wait on both. `clippy` now runs in tier 2
as an ordinary job.

`ios-xcframework` builds the XCFramework once in tier 2; `swift-test`
(`make ios-test-only`) and `ios-demo` both restore it through `wrapper-swift`
and run in parallel in tier 4. Before the split, `swift-test` built it and
`ios-demo` waited for the whole 40-minute job just to reuse it. That mirrors
`kotlin-test` and `android-demo`, which both hang off `uniffi-wrapper`.

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
Those entries can never be hit by a later run and do consume the 10 GB budget,
but GitHub evicts least-recently-used, so the wrapper entries — read once inside
their own run — are the first to go and the `target-*`/`sccache` entries the
last. Moving them to `upload-artifact` was tried and reverted: it needs a manual
tar to keep `node_modules/.bin`, whose symlinks and executable bits artifacts do
not preserve, and turns a soft cache miss into a hard failure on re-run.

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
- One sccache entry per OS, not one per job. Per-job entries reached 8.39 GB of
  the 10 GB repository ceiling and evicted the `target/` caches, which cost more
  than they saved. The key carries `runner.os` because the entry is write-once:
  a Linux job claimed it first, so `macos-15` restored ~1 GB of Linux objects
  that no Apple-target compile can ever match, and never saved its own.
  `runner.arch` is in the key for the same reason. Two
  entries stay far under the ceiling. The npm entry is keyed on content alone —
  it holds portable tarballs.
- Neither cache works for `android-demo`, and both were measured. A `target/`
  cache cannot help: it restored `target-android` on an exact key hit and cargo
  still rebuilt 2653 crates, because `actions/checkout` stamps sources newer
  than the restored artifacts and cargo compares mtimes. sccache is
  content-hashed and immune to that, but `sccache --show-stats` reported 11154
  compile requests, 10723 misses and a 0.00% hit rate, and the job went from
  26 to 30 minutes — the wrapper costs something per invocation and returned
  nothing. 6697 of those compiles are C/C++ from the NDK, not Rust, so even a
  working Rust cache addresses barely a third of the work. Measure the Gradle
  share before trying anything else here; `~/.gradle/caches` is untested.
  That job sets `RUSTC_WRAPPER` itself: `_job.yml` derives it from the
  `sccache` input and `_macos.yml` sets it at workflow level, so `_android.yml`
  has no other source. It prints `sccache --show-stats` after the AAR build.
- Actions are pinned by commit SHA, never by tag.
- The toolchain versions live in the workflow `env:` block and are read through
  `${{ env.RUST_VERSION }}` / `${{ env.NODE_VERSION }}` in step `with:` inputs.
  `jobs.<id>.container.image` cannot read the `env` context, so its tag stays a
  literal and a version bump touches the `env:` block and every `image:` line.
- `swift-test` pins `macos-15`; `macos-latest` now means `macos-26`. macOS
  bills at 10x here. The debug path no longer builds `x86_64-apple-ios`: an
  arm64 host cannot run that simulator slice — Xcode 16 dropped the `arch=`
  key, and `ARCHS=x86_64` builds a bundle the arm64 simulator refuses to load
  — so it was compiled and never tested. Testing it needs a `macos-15-intel`
  runner. The release path never built it. `ios-demo` therefore passes
  `ARCHS=arm64`: `-destination 'generic/platform=iOS Simulator'` builds every
  simulator arch, and without the pin it fails with `Undefined symbols for
  architecture x86_64`. `swift-test` needs no pin because `IOS_DESTINATION`
  names one arm64 simulator.
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
  shallow. `generic-api-key` and `jwt` stay enabled and are allowlisted by
  value shape, not by path: did:key multibase identifiers, compact JWTs and
  W3C `…Key20xx` method-type names. Those three shapes are every hit in the
  tree, and matching on them leaves both rules live in every file, so a new
  fixture needs no config change. Provider rules are untouched.
- `_job.yml` sets `CARGO_PROFILE_DEV_DEBUG` for every job from one input
  defaulting to `"0"`, rather than repeating it per job. `test-with-coverage`
  is the documented exception, passing `line-tables-only`.
- `build-dev` gates nothing; it sits in tier 2 behind `fmt` like the other builds. It is the only producer of `target-dev-*`.
- `android-demo` runs on a bare runner, not the container. The Makefile's
  `android-clang-symlinks` writes `~/.cargo/config.toml`, which cargo ignores
  when `CARGO_HOME` points at the image's `/usr/local/cargo`, losing the NDK
  linker settings. It takes the SDK preinstalled on the runner and adds only
  `ndk;$NDK_VERSION`, and gets 90 minutes: the equivalent GitLab job has hit
  the 60-minute cap.
- `demos/android` is the Kotlin demo; the job is named after the directory.
  It builds the AAR, assembles the app and runs the Kotlin unit tests. The
  instrumented tests need an emulator and are not run.
- `nodejs-demo-build` restores the `wrapper-*` caches and uses
  `npm i --ignore-scripts`, skipping the `preinstall` that would rebuild the
  wrappers its upstream jobs already built. `demo-build` cannot: `wasm-wrapper`
  leaves `pkg` holding the cjs/nodejs build from `build:dev:cjs`, since `make`
  wipes `pkg` on each run, and the wasm demo needs the web/esm one. Reusing it
  fails as `TS2349: This expression is not callable`. The wasm wrapper is built
  per consumer, so the demo must build its own.
- `multi-thread-demo` runs `cargo build` before starting the issuer. `cargo run`
  compiles inside the port wait and times out, which is why
  `demos/oid4vc/demo.sh` pre-builds too.
- `android-demo` puts the NDK's `toolchains/llvm/prebuilt/linux-x86_64/bin` on
  `PATH`. `ANDROID_NDK_HOME` alone is not enough: the `cc` crate looks up
  `aarch64-linux-android-clang` by name and `ring` fails to build without it.
- `ios-demo` reuses the XCFramework from `ios-xcframework` through `wrapper-swift`
  rather than rebuilding it — the demo's xcodeproj points at
  `wrappers/uniffi/swift/ios/debug`, which is what `ios-generate-xcframework-dev`
  writes. It has no rebuild fallback: the artifact is required, and a missing
  one fails the job rather than recompiling.
  Nothing equivalent exists for Android: `kotlin-test` builds the host target
  only, never the four Android targets or the AAR.
- `multi-thread-demo` greps for `Success`. `start_holders` panics per holder
  but still exits 0, so a plain `cargo run` would pass with every holder failed.
  The demo's issuer was built `.with_nonce_handler(...)`, which makes it reject
  proofs with no nonce, but the server exposes only `/credential` and no nonce
  endpoint, so no holder could obtain one. The SDK enforces nonces only when a
  handler is present, and the README says nonce generation is skipped here, so
  the handler is gone. `allow-failure` exists on `_job.yml` for cases like this
  but nothing sets it: `continue-on-error` cannot go on a `uses:` job, which
  accepts only name, uses, with, secrets, needs, if and permissions, so it is a
  step-level flag driven by an input.
- `android-demo` caches the four Android target directories under
  `target-android`; nothing else in the workflow builds those triples.
- `demo-build` restores `target-askar` too: its npm `preinstall` builds the
  askar napi wrapper with `CARGO_TARGET_DIR=../../target`, which resolves to
  `plugins/askar/target` — the directory `askar-rust` saves.
- `target-prod` is the only `target/` cache, and it was kept on measurement:
  removing it put `build-prod` at 11m (from 7-8m) and `nodejs-wrapper` at 15m
  (from 9-12m), both on the same chain. `build-prod` compiles only `-p nodejs`
  with the command `napi build --release` runs, so the fingerprints match and
  the wrapper's release build reuses them.
- `target-dev`, `target-askar`, `target-wasm` and `target-android` were removed.
  Each was measured: android hit its key while cargo rebuilt 2653 crates, wasm
  bought a minute for 594 MB a ref, and dropping dev left `build-dev`,
  `doc-build` and `kotlin-test` unchanged. `actions/checkout` stamps sources
  newer than restored artifacts and cargo compares mtimes, so a `target/` cache
  only survives where the consumer rebuilds with identical flags. Measure before
  adding another; the results differ per job and do not generalise.
- `cache-cleanup` deletes the five `wrapper-*` entries after a successful run.
  They are keyed on `github.sha` and can never be hit again, so they are
  intra-run hand-offs that would otherwise sit in the 10 GB budget until LRU
  eviction. It runs `if: success()`, not `always()`: deleting them after a
  failure breaks "Re-run failed jobs", which re-runs only the failed job and
  leaves its consumer with no wrapper to restore. A failed run therefore leaks
  five entries, and `prune-wrapper-caches.sh` sweeps any `wrapper-*` over three
  hours old on the next successful run. Nothing else is needed: GitHub deletes
  caches unused for seven days and evicts least-recently-used at the ceiling,
  and these entries are read once inside their own run, so they are the first
  to go. A scheduled prune was tried and dropped as redundant machinery.
- `_job.yml` installs `cargo-binstall` and `sccache` only when `sccache` is on.
  `fmt`, `nodejs-test`, `wasm-test`, `nodejs-demo-build` and
  `askar-plugin-nodejs-test` run no cargo compilation and set `sccache: false`,
  which skips the download. `wasm-wrapper` and `demo-build` also set it but do
  compile; they simply do not use the wrapper.
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
- Coverage uses no external service. `test-with-coverage` writes `Html` as an
  artifact, prints the figure to the step summary, and on `main` runs
  `scripts/coverage-badge.sh`, which commits an SVG to the orphan `badges`
  branch at `.badges/<branch>/coverage.svg`; the README reads it from
  `raw.githubusercontent.com`. That job is the only one granted
  `contents: write`. The script is idempotent — an unchanged percentage makes
  no commit — so the branch does not accumulate noise. `--fail-under 70` is
  the gate. Codecov was tried and dropped: it needs a token the repo does not
  have, answered `Token required - not valid tokenless upload`, and put a
  third party in the way of merging.
- `dependency-scan` reports advisories and does not gate, matching GitLab.
  RUSTSEC-2023-0071 has no patched release, so gating could never go green, and
  a missing report warns rather than fails — `cargo audit --json` writes
  nothing when the advisory DB is unreachable.
