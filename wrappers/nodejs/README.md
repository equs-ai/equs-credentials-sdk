# EQUS Credentials SDK wrappers for Node.js

Node.js bindings for EQUS Credentials SDK, built as a native addon with [NAPI-RS](https://napi.rs).

## Prerequisites

- Node.js and npm — see `engines` in [`package.json`](package.json)
- A Rust toolchain — see `rust-version` in [`Cargo.toml`](../../Cargo.toml)

## Installation

The wrapper is published as `@equs-ai/equs-credentials-sdk`; the native binary for your platform comes from a
companion `@equs-ai/equs-credentials-sdk-<os>-<arch>` package. Point npm at the registry that hosts them, then:

```shell
npm i @equs-ai/equs-credentials-sdk
```

From the GitLab registry, do not pass `--ignore-scripts` — the postinstall step is what resolves the platform
binary. The npmjs release carries no postinstall; npm resolves the binary from `optionalDependencies`.

## Building and testing locally

Build the native binding, then run the test suite:

```shell
npm run build:debug   # required for tests — enables the `in-memory` feature
npm test
```

`npm run build` produces the release binary without the `in-memory`
feature, so the tests will fail against it. Test files live in `test/`.

## Usage

The package can be imported with both ES module and CommonJS syntax.

## Publishing

Each platform binary is published as its own npm package, then the `@equs-ai/equs-credentials-sdk` package that
depends on them is published on top. Both steps run from the release pipeline
([`publish.yml`](publish.yml)) — see [Publish a New Release](../../docs/guidelines/release.md).

The two scripts the pipeline calls, for a manual run:

```shell
REGISTRY_URL_NPM=<registry-url> NPM_TOKEN=<token> TARGET=<target> ALIAS=<alias> ENVIRONMENT=development scripts/build_and_publish_target.sh
REGISTRY_URL_NPM=<registry-url> NPM_TOKEN=<token> ENVIRONMENT=development scripts/build_and_publish_wrapper.sh
```

Both scripts append a registry auth line to `~/.npmrc` derived from `REGISTRY_URL_NPM`, so no
`.npmrc` is committed. In CI both variables come from the pipeline; `REGISTRY_URL_NPM` is built
from `$CI_SERVER_HOST` and `$CI_PROJECT_ID`.

On GitHub, [`publish-npm.yml`](../../.github/workflows/publish-npm.yml) runs the same two scripts against npmjs
on an `npm/vX.Y.Z` tag.

The target list is `napi.triples.additional` in [`package.json`](package.json); `defaults` is off, so
`napi prepublish` lists only those three platforms in `optionalDependencies`.
