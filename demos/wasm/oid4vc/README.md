# EQUS Credentials SDK e2e demo on Web Assembly

This Demo allows to demonstrate the end-to-end flow of the OID4VCI/VP protocol on Web Assembly.

## Prerequisites

Ensure that the following tools are installed on your machine:

- [Node.js](https://nodejs.org/) and [npm](https://www.npmjs.com/) — see `engines` in `package.json`
- A Rust toolchain — see `rust-version` in [`Cargo.toml`](../../../Cargo.toml)

## Installation

Every package you need is already installed in `package.json`. If you develop further and need another dependencies -
contact maintainers.

Full installation of built dependencies of the SDK, equs-credentials-sdk-nodejs-demo is done at preinstall step so only steps required are:

```shell
  npm i
```

### Setup keycloak by [instructions](../../keycloak/README.md)

As WASM faces CORS issues - it is required to update
Keycloak [configurations](../../keycloak/realms/pid-issuer-realm-realm.json).
Add your server's host to necessary client. (currently: `"clientId": "wallet-dev"`).
If you have already built container - remove and reinstall it.

## Usage

### Build project by running:

```shell
npm run build
```

### OR

```shell
yarn run build
```

### Run applications:

WASM demo uses Node.js demo's issuer & verifier as holder sends them HTTP requests, and it is not necessary to start
them in browser.

```shell
npm run issuer
```

```shell
npm run verifier
```

```shell
npm run holder
```

### OR

```shell
yarn run issuer
```

```shell
yarn run verifier
```

```shell
yarn run holder
```

Start application:

```shell
 npx serve .
```

Install it if it is not and rerun script.

### Application

Once application started - follow steps in browser
