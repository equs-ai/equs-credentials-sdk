# Publish a New Release

A release is driven by a **git tag**. Pushing a tag named exactly `X.Y.Z` starts the release stage of the
pipeline, which builds and publishes every wrapper package.

Do the steps in order: the version bump has to be on `main` *before* the tag is created, because the
publish scripts read the version from the manifests, not from the tag name.

## 1. Pre-flight checks

1. The pipeline on `main` is green. The tag pipeline runs **only** the release stage — no build, lint or
   test jobs — so `main` is the last point at which anything is verified.
2. The demo application runs successfully and passes all flows.
3. The latest commit on `main` contains every change meant to be in the release.
4. `Cargo.toml` is bumped to the release version (step 2); the wrapper manifests ideally match.

## 2. Bump the version

Published versions come **from the tag**: every publish job sets the artifact version to
`CI_COMMIT_TAG`, so the tag and the published version cannot disagree. `Cargo.toml` is the exception —
it is not derived from the tag. The remaining declarations affect only local builds, where
`CI_COMMIT_TAG` is unset; keeping them in step is hygiene, not a publishing requirement.

| Target | File | Declaration |
| --- | --- | --- |
| Rust workspace | [`Cargo.toml`](../../Cargo.toml) | `version = "X.Y.Z"` |
| Node.js wrapper | [`wrappers/nodejs/package.json`](../../wrappers/nodejs/package.json) | `"version"` |
| WASM wrapper | [`wrappers/wasm/package.json`](../../wrappers/wasm/package.json) | `"version"` |
| Askar plugin (Node.js) | [`plugins/askar/wrappers/nodejs/package.json`](../../plugins/askar/wrappers/nodejs/package.json) | `"version"` |
| Android (Kotlin) | [`wrappers/uniffi/kotlin/android/build.gradle.kts`](../../wrappers/uniffi/kotlin/android/build.gradle.kts) | `val baseVersion` |
| iOS (Swift) | [`wrappers/uniffi/scripts/build_and_publish_ios.sh`](../../wrappers/uniffi/scripts/build_and_publish_ios.sh) | `VERSION=` |

After bumping:

1. Run `cargo build` so `Cargo.lock` picks up the new workspace version.
2. Commit `Cargo.toml`, `Cargo.lock` and the five wrapper files together.
3. Merge to `main` and wait for that pipeline to go green.

Only `Cargo.toml` is load-bearing for a release; the rest can be corrected later without republishing.

## 3. Write the release notes

Put them in a scratch file — `NOTES.md` — using the [format below](#release-notes-format). The next step
records them in the tag itself, so they travel with the repository and need no external system to be
readable.

## 4. Create and push the tag

Replace `<version>` with the release version (e.g. `1.11.0`):

```shell
git switch main
git pull
git tag -a <version> -F NOTES.md
git push origin tag <version>
```

Read the notes back at any time:

```shell
git tag -n99 <version>     # notes for one tag
git show <version>         # notes plus the commit it points at
```

Rules for the tag name:

- Exactly `X.Y.Z` — no `v` prefix, no suffix. Only this shape triggers the production publish jobs, which
  move the `latest` npm dist-tag.
- `X.Y.Z-<suffix>` (e.g. `1.14.0-rc.1`) triggers the **dev** jobs instead — see
  [Dev builds](#dev-builds). The two shapes are disjoint.
- Never re-point a tag that has already been released. Re-running a release pipeline over versions that
  already exist in the registry does not fail cleanly: most npm publishes appear to succeed but land as
  orphan `0.0.0-<uuid>` rows, and a few hard-reject. To exercise release CI, use an unused patch version
  and delete both the tag and the resulting package rows afterwards.

## 5. What the tag pipeline publishes

Each wrapper has a production job, published under the `latest` tag:

| Job | Artifact | Registry |
| --- | --- | --- |
| `publish_nodejs_target` / `publish_nodejs_wrapper` | `@equs-ai/equs-credentials-sdk` + per-platform binaries (linux-x64-gnu, darwin-arm64, darwin-x64) | npm |
| `publish_wasm_wrapper` | `@equs-ai/equs-credentials-sdk-wasm` | npm |
| `publish_askar_nodejs_target` / `publish_askar_nodejs_wrapper` | `@equs-ai/equs-credentials-sdk-askar-storage` + per-platform binaries | npm |
| `publish_android_wrapper` | `equs-credentials-sdk-android` AAR | Maven |
| `publish_ios_wrapper` | `equs-credentials-sdk-ios` XCFramework zip + checksum | package registry |
| `release_artifacts_job` | `SBOM.auto.out`, `AUDIT.auto.out`, `API.auto.tar.gz` (rustdoc) | pipeline artifacts |

The release is done once that stage finishes green.

### Dev builds

Five of the seven production jobs have a `*_dev` counterpart publishing under the `dev` npm
dist-tag: `publish_nodejs_target_dev`, `publish_nodejs_wrapper_dev`, `publish_wasm_dev_wrapper`,
`publish_ios_wrapper_dev` and `publish_android_wrapper_dev`. Dev builds are debug builds. The askar
plugin has no dev job — it declares no cargo features, so a dev build would differ from production
only in optimization level.

They run on a prerelease tag — `X.Y.Z-<suffix>`, hyphen mandatory:

```shell
git tag -a 1.14.0-rc.1 -m "dev build"
git push origin tag 1.14.0-rc.1
```

A plain `X.Y.Z` tag creates no dev job. Dev jobs run automatically, and a failure fails the pipeline.

The published dev version **is the tag** (`1.14.0-rc.1`), not `X.Y.Z-dev`, so each prerelease tag
produces a distinct version and repeat dev builds never collide. Run locally without `CI_COMMIT_TAG`
and the old `X.Y.Z-dev` naming still applies.

## npmjs

The Node.js wrapper (with its three platform packages) and the WASM wrapper are also published to
[npmjs](https://www.npmjs.com/org/equs-ai) by the GitHub workflow
[`publish-npm.yml`](../../.github/workflows/publish-npm.yml). It runs on its own tag, `npm/vX.Y.Z`, pushed to
the GitHub remote:

```shell
git tag -a npm/v<version> -F NOTES.md
git push github-equs tag npm/v<version>
```

As on GitLab, the published version is the tag, and `npm/vX.Y.Z-<suffix>` publishes a debug build under
the `dev` dist-tag. An npmjs version can never be republished, even after an unpublish, so a bad tag costs
a version number.

## Release notes format

One line per change:

```text
[feat|fix|chore] {Description}: [{Issue number}]({Issue link})
```

Example:

```text
- [feat] Add feature: #123.
- [fix] Fix bug: #124.
- [chore] Security Logging adjustments: #125
```
