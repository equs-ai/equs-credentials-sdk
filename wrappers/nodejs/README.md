# EQUS Credentials SDK wrappers for Node.js

Node.js bindings for EQUS Credentials SDK, built as a native addon with [NAPI-RS](https://napi.rs).

## Prerequisites

- Node.js and npm — see `engines` in [`package.json`](package.json)
- A Rust toolchain — see `rust-version` in [`Cargo.toml`](../../Cargo.toml)

## Installation

The wrapper is published as `@equs-ai/equs-credentials-sdk`; the native binary for your platform comes from a
companion `@equs-ai/equs-credentials-sdk-<os>-<arch>` package. Both are on npmjs:

```shell
npm i @equs-ai/equs-credentials-sdk
```

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
depends on them is published on top. Both steps run from
[`publish-nodejs.yml`](../../.github/workflows/publish-nodejs.yml) on a `nodejs/vX.Y.Z` tag — see
[Publish a New Release](../../docs/guidelines/release.md).

The two scripts the pipeline calls, for a manual run:

```shell
REGISTRY_URL_NPM=<registry-url> NPM_TOKEN=<token> TARGET=<target> ALIAS=<alias> ENVIRONMENT=production scripts/build_and_publish_target.sh
REGISTRY_URL_NPM=<registry-url> NPM_TOKEN=<token> ENVIRONMENT=production scripts/build_and_publish_wrapper.sh
```

Both scripts pack the package and publish the resulting `.tgz`, which the release manifest hashes.
Both append a registry auth line to `~/.npmrc` derived from `REGISTRY_URL_NPM`, so no
`.npmrc` is committed. In CI, `REGISTRY_URL_NPM` is `https://registry.npmjs.org/` and `NPM_TOKEN` comes
from the `EQUS_CREDENTIALS_SDK_NPM_TOKEN` org secret.

The target list is `napi.triples.additional` in [`package.json`](package.json); `defaults` is off, so
`napi prepublish` lists only those three platforms in `optionalDependencies`.
