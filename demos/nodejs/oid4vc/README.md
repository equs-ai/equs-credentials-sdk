# EQUS Credentials SDK e2e demo on Node.js
This Demo allows to demonstrate the end-to-end flow of the OID4VCI/VP protocol on Node.js.


## Prerequisites

Ensure that the following tools are installed on your machine:

- [Node.js](https://nodejs.org/) and [npm](https://www.npmjs.com/) — see `engines` in `package.json`
- A Rust toolchain — see `rust-version` in [`Cargo.toml`](../../../Cargo.toml)

## Installation

Every package you need is already installed in `package.json`. If you develop further and need another dependencies - contact maintainers.

To install use development environment as the SDK should compile with all the features:
```shell
npm i
```

### Setup keycloak by [instructions](../../keycloak/README.md)

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
Make sure to check ports of application before starting them. You can find them at [config](./src/components/config.ts)
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

### Follow the instructions in the holder terminal