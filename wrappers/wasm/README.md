

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

## How to test in NodeJS

```bash
WASM_TARGET=nodejs make
cd ./tests-js
npm install
npm test
```

## How to test in Browser

```bash
WASM_TARGET=nodejs make
cd ./test
npm install
npm run test-puppeteer
```

_Note tests will be executed with jest+puppeteer in Chromium installed inside node_modules._