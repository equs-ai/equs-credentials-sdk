# API Wrappers

## Node.js

We use the **NAPI-RS** library to generate Node.js wrappers for ASDK. After conducting research and comparing various
options, we selected this library as the most appropriate choice. The research results, including comparisons with other
options like Neon and node-bindgen, can be found at the following
link: https://blockchains-inc.atlassian.net/wiki/spaces/SDKDSR/pages/162923216/Build+ASDK+for+NodeJS#Comparing-napi-rs%2C-neon-and-node-binding-crates

### Create project

To create a **NAPI-RS** project, follow the official **NAPI-RS** instructions available
here: https://napi.rs/docs/introduction/getting-started

### Implement wrappers

To expose the Rust functions and structs to Node.js, you should use `#[napi]` macros.

#### Expose simple function

The `#[napi]` macro is used to expose Rust functions to JavaScript. Functions can be synchronous or asynchronous.The
allowed function parameters and return types are defined in the https://napi.rs/docs/concepts/function

```rust
#[napi]
fn sample(name: String) -> String {
    format!("Called with arg: {}!", name)
}

#[napi]
async fn sample_async(name: String) -> Result<Buffer> {
    // async code
}
```

#### Expose struct, methods and enums

Structures, methods, and enumerations can be exposed in a similar way to JavaScript. Structs can be converted into two
basic types:

- Classes (Structs with methods): These are passed by reference from JavaScript to Rust.
- Objects (Structs without methods): These are copied when passed to and from JavaScript.

Important considerations:

- Generic types must be resolved before they can be exposed to Node.js.
- Structured enums (with associated data) are not supported in the current stable release (2.16.11).

```rust
#[napi]
pub struct SampleStruct {
    value: i32,
}

#[napi]
impl SampleStruct {
    #[napi(constructor)]
    pub fn new(value: i32) -> Self {
        SampleStruct { value }
    }

    #[napi]
    pub fn add(&mut self, other: i32) -> i32 {
        self.value += other;
        self.value
    }
}

#[napi(object)]
pub struct SampleObject {
    pub name: String,
    pub surname: String,
}

#[napi]
pub enum SampleEnum {
    AValue,
    BValue,
}
```

See the official NAPI-RS documentation for more concepts and advanced features. Links to documentation and sample
examples can be found in the [resources](#resources) section.

### Build wrapper

To generate the wrappers for Node.js, use the following commands.

**Release Build**

```shell
yarn build
# or
npm build
```

**Debug Build**

```shell
yarn build
# or
npm build
```

### Wrapper tests

All JS test files are located in the `__test__` folder.

**Run test**

```shell
yarn test
# or
npm test
```

**Note:** Before running the tests, you may need to build the wrapper by running `yarn build`. For the ASDK wrapper
located in the `wrappers/nodejs` folder, you must run `yarn build:debug`, as the tests use functions only available in
the debug build.

### Resources

- NAPI-RS doc: https://napi.rs/docs/introduction/getting-started
- NAPI-RS examples: https://github.com/napi-rs/napi-rs/tree/main/examples
