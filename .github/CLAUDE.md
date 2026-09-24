# .github — GitHub Actions CI

GitHub Actions port of the CI half of `.gitlab-ci.yml`, plus one release job.
`.gitlab-ci.yml` is the running pipeline, so a CI change belongs in both files.
`publish-crate.yml` and `publish-common-macros.yml` are the exceptions and
have no GitLab counterpart: GitLab publishes the npm and UniFFI wrappers to its
own registry and never a crate.

Two workflows. `ci.yml` defines no jobs directly: every job calls a
reusable workflow, so `container`, checkout,
toolchain and caches are written once. Underscore-prefixed files are
`workflow_call` targets, never triggered on their own. `publish-crate.yml` and
`publish-common-macros.yml` call none of them and write their own jobs.

Because CI jobs run through `workflow_call`, a check is named `<job> / run`, not
`<job>` — branch-protection rules must use the two-part name. The publish job
is the one exception and is named `publish`.

| Path | Role |
|------|------|
| `workflows/ci.yml` | Triggers, gating and the 27 job calls. No steps. |
| `workflows/_job.yml` | The generic containerised job behind 23 of the 27. Owns `container`, checkout, toolchain, node/java/wasm, caches, disk report and artifact upload. |
| `workflows/_macos.yml` | The generic `macos-15` job behind `ios-xcframework`, `swift-test` and `ios-demo`. |
| `workflows/_android.yml` | `android-demo`: bare `ubuntu-latest`, SDK from the runner plus the pinned NDK. |
| `workflows/publish-crate.yml` | Publishes `equs-credentials-sdk` to crates.io on a `vX.Y.Z` tag, then renders its release manifest and uploads it to the release. Defines its own jobs. |
| `workflows/publish-common-macros.yml` | Publishes `equs-common-macros` to crates.io on a `common-macros/vX.Y.Z` tag, prerelease suffix allowed, then renders its release manifest and uploads it to the release. Defines its own jobs. |
| `actions/setup-rustup/` | Reclaims host disk, installs the pinned toolchain, restores the sccache and npm caches, installs `cargo-binstall` and `sccache`. |
| `actions/cache/` | Named cache presets (`target-*`, `wrapper-*`), selected by the `restore`/`save` string inputs. |
| `gitleaks.toml` | Secret-scan config. |
| `scripts/install-gitleaks.sh` | Pinned gitleaks download with its SHA256; prints the binary path. |
| `scripts/coverage-badge.sh` | Writes the coverage SVG to the `badges` branch. Runs only on `main`. |
| `scripts/binstall-or-build.sh` | Installs a `cargo-X` subcommand, falling back to a source build. Derives the check from the crate name, so it takes one argument where GitLab's `binstall_or_build` takes two. |

Jobs run in five declared tiers, marked by `# tier N` and ordered in the file:
1 `fmt` plus the two scans, which gate nothing; 2 `clippy`, `build-prod`,
`build-prod-all-features`, `build-dev`, `common-macros-test`, `doc-build` and
`ios-xcframework`; 3 the three wrappers, `test-with-coverage`,
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
- `common-macros-test` is the only job that runs `cargo test`. Coverage aside,
  `test-with-coverage` is the pipeline's only other test runner, and
  `cargo tarpaulin` at the workspace root inherits cargo's default package
  selection — the root package only. That never built
  `equs-common-macros/tests/debug_error.rs`, so the derive shipped untested.
  `cargo test -p equs-common-macros` is a couple of seconds on top of the
  container spin-up, and it has a GitLab counterpart, `common-macros-test-job`.
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
- The tag filter is the glob `v[0-9]*.[0-9]*.[0-9]*`, not a regex — GitHub
  matches `on.push.tags` by glob, so `[0-9]+` would never fire. The glob is
  deliberately loose and the `Resolve version` step strips the `v` and
  re-checks against `^[0-9]+\.[0-9]+\.[0-9]+$` and against the `[package]`
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
