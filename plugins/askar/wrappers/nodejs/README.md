# Askar Storage wrapper for Node.js

Node.js bindings for the example KMS and Vault in [`plugins/askar`](../..), built as a native
addon with [NAPI-RS](https://napi.rs).

## Prerequisites

- Node.js and npm — see `engines` in [`package.json`](package.json)
- A Rust toolchain — see `rust-version` in [`Cargo.toml`](../../../../Cargo.toml)

## Installation

The wrapper is published as `@equs-ai/equs-credentials-sdk-askar-storage`; the native binary for your platform
comes from a companion `@equs-ai/equs-credentials-sdk-askar-storage-<os>-<arch>` package. Both are on npmjs:

```shell
npm i @equs-ai/equs-credentials-sdk-askar-storage
```

## Usage

The package can be imported with both ES module and CommonJS syntax.

## Publishing

Each platform binary is published as its own npm package, then the
`@equs-ai/equs-credentials-sdk-askar-storage` package that depends on them is published on top. Both steps run from
[`publish-askar.yml`](../../../../.github/workflows/publish-askar.yml) on an `askar/vX.Y.Z` tag — see
[Publish a New Release](../../../../docs/guidelines/release.md).

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
