# EQUS Credentials SDK wrappers tests for Node.js & WASM

## Prerequisites

Ensure that the following tools are installed on your machine:

- [Node.js](https://nodejs.org/) and [npm](https://www.npmjs.com/) — see `engines` in `package.json`
- A Rust toolchain — see `rust-version` in [`Cargo.toml`](../../../Cargo.toml)

# Testing

As these tests directly depended on packages these packages MUST be build & installed as aliases.
Tests are not only package depended on but also platform depended.

Below are possible builds & their test scripts^

#### Node.js

```bash
   npm run setup:nodejs
   npm run test:nodejs
```

#### WASM

```bash
   npm run setup:wasm
   npm run test:wasm
```