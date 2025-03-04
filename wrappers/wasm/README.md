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

Build script is already included into test script so can be simply run via:

```bash
    npm run test
```
