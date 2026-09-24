# .github — GitHub Actions CI

GitHub Actions port of the CI half of `.gitlab-ci.yml`, plus one release job.
`.gitlab-ci.yml` is the running pipeline, so a CI change belongs in both files.
The `publish-*.yml` workflows are the exceptions and have no counterpart there:
`publish-crate.yml` and `publish-common-macros.yml` publish to crates.io,
`publish-nodejs.yml`, `publish-wasm.yml` and `publish-askar-nodejs.yml` to npmjs,
`publish-android.yml` to Maven Central, `publish-ios.yml` to GitHub release assets.
`release.yml` runs on the SDK's `vX.Y.Z` and calls the crate, all three npm
workflows, the Android one and the iOS one, so one tag releases everything.

Two workflows. `ci.yml` defines no jobs directly: every job calls a
reusable workflow, so `container`, checkout,
toolchain and caches are written once. Underscore-prefixed files are
`workflow_call` targets, never triggered on their own. The `publish-*.yml`
workflows call none of them and write their own jobs.

Because CI jobs run through `workflow_call`, a check is named `<job> / run`, not
`<job>` — branch-protection rules must use the two-part name. The publish job
is the one exception and is named `publish`.

| Path | Role |
|------|------|
| `workflows/ci.yml` | Triggers, gating and the 28 job calls. No steps. |
| `workflows/_job.yml` | The generic containerised job behind 24 of the 28. Owns `container`, checkout, toolchain, node/java/wasm, caches, disk report and artifact upload. |
| `workflows/_macos.yml` | The generic `macos-15` job behind `ios-xcframework`, `swift-test` and `ios-demo`. |
| `workflows/_android.yml` | `android-demo`: bare `ubuntu-latest`, SDK from the runner plus the pinned NDK. |
| `workflows/release.yml` | On a `vX.Y.Z` tag: preflight (tag is `X.Y.Z`, matches `Cargo.toml`, no package already at that version), then calls `publish-crate.yml`, `publish-nodejs.yml`, `publish-askar-nodejs.yml`, `publish-wasm.yml`, `publish-android.yml` and `publish-ios.yml`, then attaches every manifest, the AAR, the Maven bundle and the iOS zip to the one release. |
| `workflows/publish-crate.yml` | `workflow_call` only, from `release.yml`. Publishes `equs-credentials-sdk` to crates.io and renders its release manifest as the `release-manifest-crate` artifact. Defines its own jobs. |
| `workflows/publish-common-macros.yml` | Publishes `equs-common-macros` to crates.io on a `common-macros/vX.Y.Z` tag, prerelease suffix allowed, then renders its release manifest and uploads it to the release. Defines its own jobs. |
| `workflows/publish-nodejs.yml` | Publishes the Node.js wrapper and its three platform packages to npmjs on a `nodejs/vX.Y.Z` tag (`-rc.N` suffix publishes under the `rc` dist-tag), then renders its release manifest and uploads it to the release. Also called by `release.yml` with a `version` input, which then attaches the manifest instead. Defines its own jobs. |
| `workflows/publish-askar-nodejs.yml` | Publishes the askar plugin wrapper and its three platform packages to npmjs on an `askar-nodejs/vX.Y.Z` tag (`-rc.N` suffix publishes under the `rc` dist-tag), then renders its release manifest and uploads it to the release. Also called by `release.yml` with a `version` input, which then attaches the manifest instead. Defines its own jobs. |
| `workflows/publish-wasm.yml` | Publishes the WASM wrapper to npmjs on a `wasm/vX.Y.Z` tag (`-rc.N` suffix publishes under the `rc` dist-tag), then renders its release manifest and uploads it to the release. Also called by `release.yml` with a `version` input, which then attaches the manifest instead. Defines its own jobs. |
| `workflows/publish-android.yml` | Publishes the Android AAR to Maven Central on an `android/vX.Y.Z` tag (`-rc.N` allowed), then renders its release manifest and uploads it to the release. Also called by `release.yml` with a `version` input. Defines its own jobs. |
| `workflows/publish-ios.yml` | Builds the dynamic `EqusSdk.xcframework` on an `ios/vX.Y.Z` tag (`-rc.N` allowed, released as a prerelease) and attaches its zip, checksum and the release manifest to the release. Also called by `release.yml` with a `version` input. Defines its own jobs. |
| `actions/npm-version/` | Resolves the npm version and dist-tag from the `version` input or the tag and exports `CI_COMMIT_TAG`/`NPM_DIST_TAG`. Used by every npm build job, `publish-android.yml` and `publish-ios.yml`. |
| `actions/setup-rustup/` | Reclaims host disk, installs the pinned toolchain, restores the sccache and npm caches, installs `cargo-binstall` and `sccache`. |
| `actions/cache/` | Named cache presets (`target-*`, `wrapper-*`), selected by the `restore`/`save` string inputs. |
| `gitleaks.toml` | Secret-scan config. |
| `scripts/install-gitleaks.sh` | Pinned gitleaks download with its SHA256; prints the binary path. |
| `scripts/coverage-badge.sh` | Writes the coverage SVG to the `badges` branch. Runs only on `main`. |
| `scripts/binstall-or-build.sh` | Installs a `cargo-X` subcommand, falling back to a source build. Derives the check from the crate name, so it takes one argument where GitLab's `binstall_or_build` takes two. |

Jobs run in five declared tiers, marked by `# tier N` and ordered in the file:
1 `fmt` plus the two scans, which gate nothing; 2 `clippy`, `build-prod`,
`build-prod-all-features`, `build-dev`, `common-macros-test`, `test-fixtures-test`,
`doc-build` and `ios-xcframework`; 3 the three wrappers, `test-with-coverage`,
`askar-rust` and `oid4vc-demo`; 4 the tests, `askar-wrapper` and `wasm-demo-build`;
5 `askar-plugin-nodejs-test`. Every demo in `demos/` is built: `oid4vc-demo`
and `multi-thread-demo` in tier 3, and `wasm-demo-build`, `nodejs-demo-build`,
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
`kotlin-test` and `android-demo`, which both hang off `kotlin-wrapper`.

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
  free at job start, and the heaviest job (`wasm-demo-build`) peaked at 49 GB used.
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
  npm key hashes the six tracked `package-lock.json` files, not `package.json`,
  whose ranges can resolve differently without changing the key.
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
  runner. The release path builds it into the simulator slice untested. `ios-demo` therefore passes
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
- `common-macros-test` and `test-fixtures-test` are the only jobs that run
  `cargo test`. Coverage aside, `test-with-coverage` is the pipeline's only
  other test runner, and `cargo tarpaulin` at the workspace root inherits
  cargo's default package selection — the root package only. That never built
  `equs-common-macros/tests/debug_error.rs`, so the derive shipped untested, and
  it would never build `test-fixtures/tests/` either. Each is a couple of
  seconds on top of the container spin-up, and each has a GitLab counterpart:
  `common-macros-test-job` and `test-fixtures-test-job`. `test-fixtures-test`
  passes `--all-features` so the `delegate-sd-jwt` suite runs; the root
  package's own unit tests cover the fixture crate from the other direction,
  through the dev-dependency cycle, and run under `test-with-coverage`.
  `test-fixtures/*` is excluded from tarpaulin: it is a workspace path
  dependency, so tarpaulin counts its lines, and only the part the root
  package's unit tests reach would ever be covered there — the rest is covered
  by `test-fixtures-test`, which tarpaulin never runs.
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
  wrappers its upstream jobs already built. `wasm-demo-build` cannot: `wasm-wrapper`
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
- `wasm-demo-build` restores `target-askar` too: its npm `preinstall` builds the
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
  which skips the download. `wasm-wrapper` and `wasm-demo-build` also set it but do
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
- `dependency-scan` gates. `cargo audit` exits non-zero on a vulnerability and
  the job exits with that code, after the step summary is written and the JSON
  left in place for the artifact. A missing report still warns rather than
  fails — `cargo audit --json` writes nothing when the advisory DB is
  unreachable — and that check runs before the gate, so an unreachable DB fails
  with its own message rather than passing as "no vulnerabilities".
  `.gitlab-ci.yml`'s `dependency_scanning` gates the same way:
  `gitlab-cargo-audit` exits 0 whatever it finds, so it stays for the GitLab
  report and a plain `cargo audit` runs after it to fail the pipeline.
  `release_artifacts_job` keeps its `|| true` — it renders `AUDIT.auto.out` for
  a tag build and was never a gate.
- The gate can only be green because `.cargo/audit.toml` allowlists five
  advisory IDs, none of them reachable by a lockfile bump. `cargo audit` reads
  that file from the project root, so local runs and both pipelines share one
  list. Only `vulnerability` is denied, which is cargo-audit's default; the 29
  `unmaintained`, `unsound` and `yanked` warnings are reported and do not gate.
  - RUSTSEC-2023-0071, `rsa` 0.6.1 and 0.9.10 — the Marvin timing attack.
    `patched = []`: no fix has ever been released, and 0.10.0-rc is affected
    too. Reached through `ssi-jwk` → `isomdl` → `equs-oid4vci`, and through
    `openidconnect`. It drops out only when those stop pulling `rsa`.
  - RUSTSEC-2026-0098, -0099 and -0104, `rustls-webpki` 0.101.7 — patched in
    0.103, which `rustls` 0.21 cannot take. The chain is `ssi` 0.16 →
    `reqwest` 0.11 → `hyper-rustls` 0.24 → `rustls` 0.21.
  - RUSTSEC-2026-0258, `h2` 0.3.27 — patched in 0.4, which `hyper` 0.14 cannot
    take. Both the SDK's own `hyper` dependency and `reqwest` 0.11 hold it there.
  Upgrading `ssi` 0.16 and `hyper` 0.14 clears four of the five; nothing clears
  the `rsa` one. Four of the nine findings the gate first saw were ordinary
  lockfile bumps and were taken instead of allowlisted: `crossbeam-epoch`
  0.9.21, `h2` 0.4.19, `quinn-proto` 0.11.18 and `rustls` 0.23.45. `rustls`
  needed `cargo update --precise`; a plain update stops at 0.23.43.
- `publish-crate.yml` does not call `_job.yml`. A reusable workflow reaches a
  secret only through a declared `secrets:` input or `secrets: inherit`, and
  adding the registry token to the job that runs 21 of the 25 CI jobs would
  put the registry token in reach of every one of them for the benefit of a
  single caller. It reuses `actions/setup-rustup` and repeats the eight lines
  of job scaffolding instead. It passes `tooling: 'false'`: the publish build
  runs once on a cold cache, so `sccache` would only cost a download.
- The publish runs `cargo package --locked` and then
  `cargo publish --locked --no-verify`. `cargo publish` on its own repeats the
  whole verification build that `cargo package` already did, and this crate is
  not cheap to compile. `--no-verify` here means "already verified in the
  previous step", not "unverified". Dropping `--locked` would let the release
  resolve dependencies the tested `Cargo.lock` never saw.
- The tag filter is the glob `v[0-9]*.[0-9]*.[0-9]*` on `release.yml`, not a regex — GitHub
  matches `on.push.tags` by glob, so `[0-9]+` would never fire. The glob is
  deliberately loose; `release.yml`'s preflight, and again the `Resolve version`
  step, strip the `v` and re-check against `^[0-9]+\.[0-9]+\.[0-9]+$` and against the `[package]`
  version in `Cargo.toml`, failing before anything is uploaded. A crates.io
  version can be yanked but never removed, so the mismatch has to be caught
  before the upload, not after. crates.io receives `X.Y.Z`; the `v` is
  git-only. Prereleases publish nothing here.
- Two prerequisites live in settings, not in the tree: the organization secret
  `EQUS_CREDENTIALS_SDK_CRATES_IO_TOKEN`, and an environment named `crates-io`.
  Being an org secret it does not appear in `gh secret list --repo` — check
  `gh api repos/:owner/:repo/actions/organization-secrets`. Cargo reads
  `CARGO_REGISTRY_TOKEN`, so the step maps the secret onto that name. The
  environment exists to carry a required-reviewer rule on an irreversible
  action; a missing environment does not fail the run, a missing secret fails
  at the guard in the `Publish` step before cargo is invoked.
- crates.io rejects a package with any `git` dependency and any path dependency
  without a `version` key. Both blocked this workflow until the forked
  dependencies moved to the published `equs-*` crates and `common-macros` was
  renamed and published; `cargo package` succeeds now.
- `publish-common-macros.yml` does not call `_job.yml`. `_job.yml` has no
  `secrets:` surface, and threading a registry token through the workflow that
  runs all 27 CI jobs would widen that blast radius for one consumer. It is the
  only workflow that declares its own `container` and steps.
- It runs `cargo package` and then `cargo publish --no-verify`, not `cargo
  publish` alone. `cargo package` already builds and verifies the tarball;
  letting publish verify again would repeat that build for nothing, and the
  packaged `.crate` is uploaded as an artifact either way.
- The tag filter is the glob `common-macros/v[0-9]*.[0-9]*.[0-9]*` backed by a
  regex guard in the job. GitHub tag globs cannot express `X.Y.Z` — the glob
  admits `common-macros/v1.2.3.4` and the guard is what rejects it. The guard
  also fails the run when the tag disagrees with
  `equs-common-macros/Cargo.toml`, because a wrong version on crates.io can be
  yanked but never removed.
- A prerelease tag is accepted: `common-macros/v0.1.0-rc.1`. The version part
  matches `.gitlab-ci.yml`'s `VERSION_REGEX`
  (`[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?`), so the prerelease alphabet is
  the repo's, not semver's in full. The tag must still equal the manifest
  exactly, so shipping `v0.1.0-rc.1` means `version = "0.1.0-rc.1"` in
  `equs-common-macros/Cargo.toml` — a prerelease on crates.io is never picked up
  by a plain `0.1` requirement, which is the point of cutting one. The trigger
  glob needed no change: its trailing `*` already absorbs `-rc.1`.
- Two prerequisites live in repo settings, not in the tree: the
  organization secret `EQUS_CREDENTIALS_SDK_CRATES_IO_TOKEN`, and an
  environment named `crates-io`. It is an org secret, so it does not appear in
  `gh secret list --repo` — check
  `gh api repos/:owner/:repo/actions/organization-secrets`. Cargo reads
  `CARGO_REGISTRY_TOKEN`, so the step maps the secret onto that name. A
  missing environment does not fail the run; a missing secret fails at the
  guard in the Publish step. The environment is where a required-reviewer rule
  on an irreversible publish belongs.
- `equs-common-macros` releases on `common-macros/vX.Y.Z`, independent of the
  SDK's `vX.Y.Z`. The two globs are disjoint, so neither release fires the
  other's workflow. Neither matches `.gitlab-ci.yml`'s bare
  `RELEASE_VERSION_REGEX`, so the crates release on GitHub and the npm and
  UniFFI wrappers release on GitLab without either tag firing the other's
  pipeline. The crate version is therefore independent of the wrappers'.
- `publish-nodejs.yml` releases on `nodejs/vX.Y.Z`, `publish-wasm.yml` on
  `wasm/vX.Y.Z` and `publish-askar-nodejs.yml` on `askar-nodejs/vX.Y.Z`, disjoint from each
  other and from the crate's `vX.Y.Z`, so each package releases on its own. The published version is the tag
  (the wrapper scripts and the WASM `Makefile` read `CI_COMMIT_TAG`, which the
  workflow sets from it); `package.json` versions are not checked.
  `X.Y.Z` publishes under the `latest` dist-tag and `X.Y.Z-rc.N` under `rc`;
  both are release builds (`ENVIRONMENT=production`, dist-tag from
  `NPM_DIST_TAG`), so no dev packages ship to npmjs. Any other suffix fails the
  version guard.
- There is no `version` job. Every build job runs `actions/npm-version` right
  after checkout: it takes the `version` input or strips the tag prefix,
  rejects anything but `X.Y.Z` or `X.Y.Z-rc.N`, and exports `CI_COMMIT_TAG` and
  `NPM_DIST_TAG` to the job. The wrapper job re-exports the version as an
  output for `manifest`. A bad tag therefore fails each build job
  after its environment approval, not before it.
- The Node.js and askar workflows run each wrapper's `build_and_publish_target.sh` per
  platform (`linux-x64-gnu` in the bookworm container for its glibc,
  `darwin-arm64`/`darwin-x64` on `macos-15`), then
  `build_and_publish_wrapper.sh` once every platform package is up, so the
  wrapper never references a missing binary. `REGISTRY_URL_NPM` points the
  scripts at npmjs and `npm_config_access=public` makes the scoped packages
  public. `publish-wasm.yml` mirrors `publish_wasm_wrapper`. The askar wrapper
  job builds the SDK wrapper first: the plugin's TypeScript imports its types
  through a local-path devDependency.
- Every publish packs first and publishes the `.tgz` (`npm pack`, then
  `npm publish <tarball>`), and uploads it as an `npm-*` artifact only once
  `npm publish` succeeded. The `manifest` job collects them and runs
  `scripts/npm_release_manifest.sh`, so each digest is the file npm received,
  and attaches `release-manifest.yaml` to the tag's release. Unlike the crate
  workflows it runs only when every publish job succeeded: a failed publish
  writes no manifest, and re-running an already-published tag fails at
  `npm publish` and leaves the existing manifest alone. After a transient
  failure, "Re-run failed jobs" keeps the earlier jobs' artifacts, so the
  manifest still covers every package. The darwin matrix sets
  `fail-fast: false`: a cancelled sibling could have published without
  uploading its tarball, and its re-run would then fail at `npm publish`
  with no artifact left for the manifest.
- `release.yml` is the only trigger for `vX.Y.Z`; `publish-crate.yml` has no
  tag trigger of its own. `crate` runs first and the three npm calls need it, so
  a crate failure publishes nothing and the wrappers never ship ahead of the
  crate. The per-package tags keep working on their own. Preflight fails the run before
  any job publishes when the tag is not `X.Y.Z`, disagrees with `Cargo.toml`,
  or any of the ten packages (crate plus nine npm) already has that version:
  crates.io and npmjs both refuse a republish, so a half-published release
  could never be completed. Global rcs are not accepted. The wrappers publish
  at the crate's version under `latest`.
- Called workflows share the caller's run, and with it the artifact
  namespace, so every artifact name carries its package: `npm-nodejs-*`,
  `npm-askar-nodejs-*`, `npm-wasm`, `maven-android`, `ios`, `release-manifest-<package>`. When called,
  a wrapper's `manifest` job still renders and uploads its artifact but skips
  the release upload (`if: ${{ !inputs.version }}`); `release.yml`'s `release`
  job, which needs all six, attaches them as
  `release-manifest-{crate,nodejs,askar-nodejs,wasm,android,ios}.yaml`. The caller grants
  `contents: write` to the wrapper calls because a called job cannot exceed
  its caller's permissions. "Re-run failed jobs" reruns only the failed
  packages and not preflight, but on the tag's original commit: it recovers a
  transient failure (network, runner), never one that needs a code change.
  A crate failure left nothing published: fix, then delete and re-push the
  tag on the fixed commit. A wrapper
  failure after the crate shipped is finished with that wrapper's own tag
  (`nodejs/vX.Y.Z`, `askar-nodejs/vX.Y.Z`, `wasm/vX.Y.Z`, `android/vX.Y.Z`, `ios/vX.Y.Z`) at the same version,
  whose manifest then lands on that tag's release instead.
- `publish-ios.yml` publishes to no registry: the release assets are the
  distribution. `ios` runs on `macos-15` with 120 minutes and runs
  `make ios-generate-framework`, which compiles the bindings into a dynamic
  `EqusSdk.xcframework` (see `wrappers/uniffi/scripts/build_ios_framework.sh`).
  It fails if either the `ios-arm64` or the `ios-arm64_x86_64-simulator`
  framework is missing or has no `.swiftinterface`, then packs
  `equs-credentials-sdk-ios-<v>.xcframework.zip` (`EqusSdk.xcframework` at the
  zip root, for `.binaryTarget(url:checksum:)`) and its `.checksum`. The step
  summary prints the `binaryTarget` snippet. The zip goes up as the `ios`
  artifact; `manifest` renders `scripts/file_release_manifest.sh` and, on an
  `ios/vX.Y.Z` tag, creates the release (a prerelease for `-rc.N`) and uploads
  everything; `release.yml`'s `release` job does it on `vX.Y.Z`. Consumers pin the XCFramework zip's checksum, so a rebuilt zip under
  the same name breaks them: `ios` fails before building when the tag's
  release already has an `equs-credentials-sdk-ios-*` asset. Within one run
  the uploads use `--clobber`, since a re-run uploads the same artifact bytes.
  `DRY_RUN` does not apply; there is nothing to dry-run. No secrets, no
  environment.
- Off by default: adding `DRY_RUN: "1"` to the `env` of `publish-crate.yml`, `publish-nodejs.yml`,
  `publish-askar-nodejs.yml` and `publish-wasm.yml` turns every `cargo publish`
  and `npm publish` into `--dry-run` and lifts the npm token guard; every job
  still builds, packs and renders its manifest. The wrapper scripts read the
  same variable.
- Prerequisites in settings: the repo secret `NPM_TOKEN` (an npm automation
  token with publish rights on the `@equs-ai` scope) and an environment named `npmjs`. Every publishing
  job uses the environment, so a required-reviewer rule prompts twice for a
  Node.js release (platforms, then wrapper) and once for WASM.
- `publish-android.yml` runs on a bare `ubuntu-latest` for the same reason as
  `android-demo`, with 120 minutes. It builds the four targets with
  `make android-generate-bindings android-copy-libs`, then
  `publishReleasePublicationToStagingRepository` builds, signs and stages the
  AAR, sources, javadoc, POM and module into `android/build/staging`. The job
  fails if the AAR lacks any of the four `jni/<abi>/libequssdk.so` or nothing
  was signed. The version directory is zipped (no `maven-metadata.xml`) and
  POSTed to the Central Portal's `upload?publishingType=AUTOMATIC`, then
  `status` is polled until `PUBLISHING` or `PUBLISHED`; `FAILED` prints the
  Portal's errors. `DRY_RUN` skips the upload and still builds, signs and
  renders the manifest. The AAR and the signed Maven bundle zip are attached
  to the GitHub release, by `manifest` on an `android/vX.Y.Z` tag and by
  `release.yml`'s `release` job on `vX.Y.Z`.
- Its prerequisites: the secrets `MAVEN_CENTRAL_TOKEN_USERNAME` /
  `MAVEN_CENTRAL_TOKEN_PASSWORD` (a Central Portal user token) and
  `MAVEN_CENTRAL_SIGNING_PRIVATE_KEY` (ASCII-armoured) /
  `MAVEN_CENTRAL_SIGNING_PRIVATE_KEY_PASSWORD`, an environment named
  `maven-central`, and the verified Portal namespace `ai.equs` (org Equs),
  which is also the groupId; the Kotlin package stays `com.equs.credentials`.
  The signing key's public half must be on a keyserver Central queries
  (keys.openpgp.org, keyserver.ubuntu.com). A Maven Central version can never
  be replaced or deleted, so `release.yml`'s preflight also checks
  `repo1.maven.org` for the POM.
