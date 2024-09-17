# Tests design

## Types of tests

We create two types of tests:

- **Unit tests** for testing a small piece of functionality
- **E2E tests** for testing all layers of the system interacting to each other

We don't create dedicated integration tests (at least, for now), instead we implement our unit tests
testing a piece of code not in full isolation from it's dependencies, but using real code where it makes sense.
It lets us implement tests easier reusing our `in-mem` components (`LocalKms`/`InMemVault`/etc)
instead of creating mocks where it is not necessary.

### Unit tests

#### Location in the code

Unit tests should be placed in the same file where the tested code is located.

The `tests` module is created for unit tests. The module must be annotated with `#[cfg(test)]`.
Each function in the `tests` module that considered to be a unit test must be annotated with `#[tokio::test]`.

Example:

```rust
...

#[async_trait]
impl<IS, HC> api::Issuer for IssuerService<IS, HC>
where
    IS: vc::core::Issuer,
    HC: HttpClient,
{
    async fn issue_credential(
        &self,
        cred_request: &CredentialRequest,
        token: &str,
        claims: &Claims,
        session: &mut IssuanceSession,
    ) -> Result<CredentialResponse> {
        ...
    }

    ...
}


#[cfg(test)]                                // tests module annotation
mod tests {
    use super::*;                           // use all names from parent module for convenience


    #[tokio::test]                          // test function annotation
    async fn issuance_fails_with_invalid_proof_error_when_nonce_is_not_provided() {
        let issuer = build_issuer().await;

        let iss_result = issuer.issue_credential(
            &sample_credential_request(),
            ACCESS_TOKEN,
            &sample_claims(),
            &mut sample_session_without_nonce(),
        ).await;

        assert!(is_protocol_error_type(iss_result.err().unwrap(), ErrorType::InvalidProof));
    }

    ...
}
```

All test functions (marked with `#[tokio::test]`) should be located before any helper functions.
It allows to find and read tests quickly due to placing them together (not mixing them with helper functions).
The structure of unit tests should look so:

```rust
#[cfg(test)]
mod tests {

    // list of `use` expressions

    use super::*
    ...
    ...

    // list of constants used in tests

    const ISSUER_URL: &str = "https://issuer-backend.com";
    ...
    ...

    // list of tests

    #[tokio::test]
    async fn holder_requests_token_correctly() {
        ...
    }
    ...
    ...

    // list of helper functions

    fn sample_issuer_metadata() -> IssuerMetadata {
        ...
    }
    ...
    ...
}
```

#### Location helper functions and fixtures in the code

It is often convenient to have some helper functions and/or test fixtures shared between several modules.

There are two possible place where you should place the shared functions depending on whether
the code is crate-level or module-level:

- crate-level code should be located in the `crate::utils::test_utils` module
- module-level code should be placed in the module where the tested code is located (for example, `oid4vci` module)

Do not use intermediate-level modules (for example, `vc` module) because it may increase complexity of the test code
scattering it between multiple places.

For example, there is a shared code used by `Holder`/`Issuer` tests simultaneously.
Such shared code used by several modules, but not by all modules in the crate, should be placed in
the module where the tested code is located (`oid4vci` module in this case).

At the same time, there are some code that should be shared on the crate-level. For example,
function `create_did_and_key_metadata()` is used by several modules, including `oid4vci`/`oid4vp`.
Such code should be placed in the `crate::utils::test_utils` module.

#### Async tests

We need to avoid blocking calls in tests. That's why we need to use `async` functions marked with `#[tokio::test]`.

Example:

```rust
    #[tokio::test]
async fn holder_requests_token_correctly() {
    ...
}
```

#### What to test?

Unit test should test a single unit of behavior.
For example Holder requesting credentials performs multiple actions:

1. generating the credential requests
2. sending request to an Issuer
3. parsing a credentil response
4. handling errors if any

Unit of behavior is how the tested system behaves in particular conditions.

All above actions are done in a single method `request_credential()` but there are several `units of behavior`
in the method. For example:

1. Generating correct body of credential request and sending it to an Issuer in case input arguments are valid
2. Returning an Error object in case input parameters are not valid
3. Returning valid `Credential` object in case the Issuer provided correct credential response
4. Returning an Error object in case the Issuer provided malformed response

Note that a single action under the method's hood gives us several units of behaviour we need to test. There are, at
least, positive and negative cases for almost each actions done by the tested system.

As a result we need to create multiple tests for the same method to cover all it's `units of behavior` under the hood.

#### Unit tests naming

Rules:

- **Test name must explicitly tell whether successful or failure case is tested**
- **Test name should describe a unit of tested behavior**
- **No rigid naming policy**. It is difficult to describe complex behavior in case there is a strict naming convention.
- **Name the test as if you were describing the scenario to a non-programmer** who is familiar with the problem domain
- **It's preferable to keep test name short**

Examples:

- `issuer_creates_credential_offer_correctly` tests successful case, the word `correctly` tells us that credential offer
  body is not malformed.
- `issuance_succeeds_when_nonce_is_provided` tests successful case, the word `succeeds` tells us that process of
  issuance performed with no errors.
- `issuance_fails_with_invalid_proof_error_when_nonce_is_not_provided` tests failure case, the word `fails` tells us
  that process of issuance performed with expected error, `with_invalid_proof_error` tells what exactly error we
  expect, `when_nonce_is_not_provided` describes condition causes such a result.

Links:

- [Unit test naming recommendations](https://enterprisecraftsmanship.com/posts/you-naming-tests-wrong/)

### E2E tests

#### E2E tests naming convention

TBD

#### E2E tests location

E2E tests should be placed in the `tests` directory of in the project's root (next to `src`).

Each test is located in a separate file. For example:

```
agent-sdk
└── tests
    ├── e2e_credential_issuance.rs
    ├── ...
    └── ...
```

#### Code shared between several E2E tests

In case we need to use some functions from more than one e2e test such functions should be placed
in a separate module in a file `tests/<SHARED_MODULE_NAME>/mod.rs`.

For example, we need to create a `common` module that includes helper functions called from several
e2e tests. Structure of files looks as shown below:

```
agent-sdk                          # root project directory
└── tests                          # directory for intergaration tests
    ├── common                     # `common` module directory
    │   └── mod.rs                 # .rs file that includes code of the `common` module
    └── e2e_credential_issuance.rs # example of integration test
```

Example of the `e2e_credential_issuance.rs` file:

```rust
use agent_sdk::vc::oid4vci::IssuerService;  // bring the tested code into test's scope

mod common;                                 // add the `common` module's code into test's crate

#[tokio::test]                              // annotate the test's function
fn issue_credentials() {
    common::setup();                        // call a function from the `common` module
    ...
}
```

## Testing tools

- `mockall`
- `rstest`
- `mockito` (will be removed in the future)

## Test coverage

We compared several code coverage tools for our Rust project:

- **Tarpaulin:** Easy to configure and set up with Continuous Integration (CI). It supports generating code coverage
  using either `Ptrace` or `LLVM` modes. The `Ptrace` mode is only available on Linux with x86_64 architecture.
  Tarpaulin provides fairly reliable line coverage but may sometimes produce minor inaccuracies.
- **gcov:** Uses LLVM IR to count covered lines, but it is not known for high accuracy in terms of code coverage.
- **go-kcov:** A wrapper around kcov, which use DWARF debugging information to generate coverage reports. While it
  can be used with Rust projects, it may not offer the same level of accuracy or ease of setup as other tools.
- **Source-based coverage (LLVM-based coverage):** This method is considered highly accurate because it instruments
  the code at the LLVM IR level, providing precise coverage data at the source level.

After reviewing the reports produced by these tools, we found that Tarpaulin with `Ptrace` mode met our accuracy
requirements and better integrated with our existing CI pipeline.

We initially set the minimum coverage to **60%**, but we need to increase it to **80%** to ensure code robustness.

### Running Code Coverage with Tarpaulin

Install Tarpaulin:

```shell
cargo install cargo-tarpaulin
```

Run Tarpaulin:

```shell
cargo tarpaulin --all-features --exclude-files demos/*
```

Run Tarpaulin with the generation of an HTML report:

```shell
cargo tarpaulin --all-features --exclude-files demos/* -o HTML --output-dir target
```