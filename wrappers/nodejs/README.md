# Equs SDK wrappers for Node.js

## Prerequisites

Ensure that the following tools are installed on your machine:

- [Node.js](https://nodejs.org/) (version >= v10.16.0+)
- [npm](https://www.npmjs.com/) (version >= v11.8.0+)
- [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) (version >= 12.0.0)

[Documentation](#package) for Equs SDK <b style="color:lightblue">integrators</b>

[Documentation](#development) for Equs SDK <b style="color:green">developers</b>

# Package

## Installation

There are package of Equs SDK (equs-sdk) and its sub dependencies containing binaries for different platform. (
equs-sdk-os-arch)

1. You need to make sure you can connect to [packages storage](https://git.slock.it/equstng/).
2. Update global npm configs (Yes, this is necessary because Equs SDK does not see where to download binary packages)
    1. Get your personal token from [gitlab](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)
    2. Add next configs to your ~/.npmrc
       ```text
       @equs:registry=https://git.slock.it/api/v4/projects/1387/packages/npm/
       //git.slock.it/api/v4/projects/1387/packages/npm/:_authToken="${PERSONAL_ACCESS_TOKEN}"
       ```
       or you can run next scripts with your tokens
       ```shell
       npm config set registry https://git.slock.it/api/v4/projects/1387/packages/npm/
       ```
       ```shell
       npm config set //git.slock.it/api/v4/projects/1387/packages/npm/:_authToken ${PERSONAL_ACCESS_TOKEN}
       ```
3. Install Equs SDK. Do not ignore postinstall script for Equs SDK (Simply do not use --ignore-scripts)
   ```shell
   npm i @equs/equs-sdk
   ```
   For development - use tag `dev`
   ```shell
   npm i @equs/equs-sdk@dev
   ```
   Or exact version with -dev postfix
   ```shell
   npm i @equs/equs-sdk@0.5.0-dev
   ```

# Development

## Installation

Follow these steps to install Node.js wrapped Equs SDK as dependency to your Node.js project:

1. **Add dependency to your package.json**:

   ```shell
   npm install equs-sdk@git+ssh://git@git.slock.it/equstng/equs-sdk/equs-sdk
   ```

   ```shell
   yarn add equs-sdk@git+ssh://git@git.slock.it/equstng/equs-sdk/equs-sdk
   ```

   You can specify package alias instead of `equs-sdk`

2. **Default postinstall**:
   Package contains default post install scripts that builds wrappers and make it possible for you to import them and
   use.
   You only need installed npm & cargo for it to run successfully.

## Building & testing locally

Build the native binding, then run the test suite:

```shell
npm run build:debug   # required for tests — enables the `in-memory` feature
npm test
```

`npm run build` produces the release binary (profile `release-strip`) without the `in-memory`
feature, so the tests will fail against it. Test files live in `test/`.

## Usage

After installation you can import package in both es modules & commonjs syntax.

## Publishing

Publishing is made with flow of building binaries to targets & publishing each binary in its npm package & publishing
`equs-sdk` package that depends on those binaries

### CI/CD

Publishing is automated in ci/cd pipelines [publish.yml](../../wrappers/nodejs/publish.yml)

### Manual

For manual publishing you need to build binaries for [targets](../../wrappers/nodejs/package.json) (list is located
at napi.name.triples.additional).
After building you need to move each binary in its [package directory](../../wrappers/nodejs/npm)
Next, publish it using

`NPM_TOKEN=<PERSONAL_ACCESS_TOKEN> npm publish --registry=https://git.slock.it/api/v4/projects/1387/packages/npm/`

All this job is done by one single script and all you need to do - run it with correct variables

`NPM_TOKEN="token" TARGET="target" ALIAS="alias" ENVIRONMENT=development scripts/build_and_publish_target.sh`

Publishing wrapper itself (without binaries in it) is a different job that is done by next script

`NPM_TOKEN="token" TARGET="target" ALIAS="alias" ENVIRONMENT=development scripts/build_and_publish_wrapper.sh`
