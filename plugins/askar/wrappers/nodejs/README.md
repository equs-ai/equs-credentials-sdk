# Askar Storage wrapper for Node.js

## Prerequisites

Ensure that the following tools are installed on your machine:

- [Node.js](https://nodejs.org/) (version >= v10.16.0+)
- [npm](https://www.npmjs.com/) (version >= v11.8.0+)
- [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) (version >= 12.0.0)

[Documentation](#package) for **Agent-SDK Askar Storage** <b style="color:lightblue">integrators</b>

[Documentation](#development) for Agent-SDK Askar Storage <b style="color:green">developers</b>

# Package

## Installation

There are package of ASDK Askar Storage (agent-sdk-askar-storage) and its sub dependencies containing binaries for
different platform. (
agent-sdk-askar-storage-os-arch)

1. You need to make sure you can connect to [packages storage](https://git.slock.it/equstng/).
2. Update global npm configs (Yes, this is necessary because ASDK does not see where to download binary packages)
    1. Get your personal token from [gitlab](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)
    2. Add next configs to your ~/.npmrc
       ```text
       registry=https://git.slock.it/api/v4/projects/1387/packages/npm/
       //git.slock.it/api/v4/projects/1387/packages/npm/:_authToken="${PERSONAL_ACCESS_TOKEN}"
       ```
       or you can run next scripts with your tokens
       ```shell
       npm config set registry https://git.slock.it/api/v4/projects/1387/packages/npm/
       ```
       ```shell
       npm config set //git.slock.it/api/v4/projects/1387/packages/npm/:_authToken ${PERSONAL_ACCESS_TOKEN}
       ```
3. Install Askar Storage. Do not ignore postinstall script for Askar Storage (Simply do not use --ignore-scripts)
   ```shell
   npm i @equstng/agent-sdk-askar-storage
   ```

# Development

## Installation

Follow these steps to install Node.js wrapped Askar Storage as dependency to your Node.js project:

1. **Add dependency to your package.json**:

   ```shell
   npm install agent-sdk@git+ssh://git@git.slock.it/equstng/agent-sdk/agent-sdk
   ```

   ```shell
   yarn add agent-sdk@git+ssh://git@git.slock.it/equstng/agent-sdk/agent-sdk
   ```

2. **Default postinstall**:
   Package contains default post install scripts that builds wrappers and make it possible for you to import them and
   use.
   You only need installed npm & cargo for it to run successfully.

## Usage

After installation you can import package in both es modules & commonjs syntax.

## Publishing

Publishing is made with flow of building binaries to targets & publishing each binary in its npm package & publishing
`agent-sdk-askar-storage` package that depends on those binaries

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

`NPM_TOKEN="token" TARGET="target" ALIAS="alias" ENVIRONMENT=development scripts/build_and_publish_wrapper.sh`********