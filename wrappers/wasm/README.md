# EQUS Credentials SDK wrappers for WASM

## How to build

Install `wasm-pack` from https://rustwasm.github.io/wasm-pack/installer/ and then

```bash
make # Will output modules best-suited to be bundled with webpack
WASM_TARGET=nodejs make # Will output modules that can be directly consumed by NodeJS
WASM_TARGET=web make # Will output modules that can be directly consumed in browser without bundler usage
```

### How to build with `wasm-pack build`

```bash
wasm-pack build # Will output modules best-suited to be bundled with webpack
wasm-pack build --target=nodejs # Will output modules that can be directly consumed by NodeJS
wasm-pack build --target=web # Will output modules that can be directly consumed in browser without bundler usage
```

### Note tests are run in Node.js environment thus need WASM package with Node.js target.

Default build is aimed at web target. In order to build for Node.js run:

```bash
    make WASM_TARGET=nodejs
```

Wrappers should be built before testing

```bash
    npm run build:nodejs
    npm run test
```

### Compilation Issues on macOS with Apple Clang

When compiling Rust projects targeting `wasm32-unknown-unknown` on macOS, you might encounter errors like:

```bash
warning: ring@0.17.14: error: unable to create target: 'No available targets are compatible with triple "wasm32-unknown-unknown"'
```

This issue often arises because Apple's version of the Clang compiler doesn't support the
`wasm32-unknown-unknown target`. To resolve this:

1. Install LLVM via Homebrew:

```bash
brew install llvm
```

2. Update Your PATH to Use LLVM's Clang:

```bash
echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

3. Verify the Installation:

```
clang --version
```
