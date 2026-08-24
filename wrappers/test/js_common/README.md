# Equs SDK wrappers tests for Node.js & WASM

## Prerequisites

Ensure that the following tools are installed on your machine:

- [Node.js](https://nodejs.org/) (version >= v10.16.0+)
- [npm](https://www.npmjs.com/) (version >= v11.8.0+)
- [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) (version >= 12.0.0)

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