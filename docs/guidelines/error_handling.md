# Overview

We use the `snafu` library for error handling, taking advantage of its features to provide more detailed and
user-friendly error messages. The following guidelines ensure consistency and clarity in how errors are handled and
reported in our codebase.

## Rules

- Developers should try to write more informative error messages, including relevant error details and arguments.
- Use the `#[derive(Snafu, DebugError)]` macro for defining error enums or structs.
- Do not use the `#[derive(Debug)]` macro for errors. The default `Debug` implementation displays internal error
  structure details that are not readable enough.
- When naming error variants, avoid adding the `Error` postfix to the variant name. The context provided by the error
  name should be sufficient.
- If an error contains a nested source error, include a `Location` struct to capture and display where the error
  occurred.
- Use the `#[snafu(implicit)]` attribute for the `location` field to avoid providing it during error creation.
- Use the `ensure!` macro if you want to raise an error if some condition is not met.
- All error enums should use the `#[non_exhaustive]` macro to allow for future extensions without breaking existing
  code.
- Error types should be placed close to their fallibility unit.
- Avoid creating a generic `errors.rs` file that may contain multiple error types, as it can become bloated.

## Error Log Example

As shown in the example below, error logs should be structured to provide useful information to the end user:

```
Internal error at src/common/catalog/src/error.rs:80:10
 Cause: Crypto error at src/common/function/src/error.rs:90:10
  Cause: BLS12-381 algorithm is not supported
```

# Common error types

## Specific operation error

These error types should be as descriptive as possible and should not require additional context such as location
information.

```rust
pub enum Error {
    #[snafu(display("Unsupported key: {type_}"))]
    KeyNotSupported { type_: String },
    #[snafu(display("Unsupported algorithm: {alg}"))]
    AlgNotSupported { alg: String },
    // Other errors    
}
```

When creating these errors, providing arguments without detailed descriptions is usually sufficient.

```rust
fn check_algorithm(alg: &str) -> Result<(), Error> {
    match alg {
        "RS256" => Ok(()),
        _ => AlgNotSupportedSnafu { alg }.fail(),
    }
}
```

## Module general error

Describes a general error and should provide additional context through detailed descriptions. Location will be
added by the DebugError macro if possible

```rust
#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Signature verifying error: {details}"))]
    SignatureVerification {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Key generation error: {details}"))]
    KeyGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    // Other errors     
}
```

For this error type a detailed description should be provided during creation.

```rust
fn verify_signature(data: &[byte], signature: &[byte]) -> Result<(), Error> {
    ensure!(
        valid_signature(data, signature),
        SignatureVerificationSnafu {
            details: "Signature does not match expected value",
        },
    );
    Ok(())
}
```

## External module/crate errors

Describes the underlying module/crate error, and should include the original source error and the location within the
module where it occurred. The implicit `location` lets Snafu record where the error occurred, and `source` tells it which error is being wrapped.

```rust
#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Crypto error"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error
    },
    #[snafu(display("Network error"))]
    Network {
        #[snafu(implicit)]
        location: Location,
        source: reqwest::Error
    },
    // Other errors     
}
```

These errors are usually created using the context function along with the appropriate error variant.

```rust
fn perform_network_request(url: &str) -> Result<Response, Error> {
    reqwest::get(url).await.context(NetworkSnafu)
}
```

# Error Example

```rust
use snafu::{Snafu, ResultExt};
use common_macros::DebugError;

#[derive(Snafu, DebugError)]
#[non_exhaustive]
enum Error {
    #[snafu(display("Unsupported key: {type_}"))]
    KeyNotSupported { type_: String },
    #[snafu(display("Unsupported algorithm: {alg}"))]
    AlgNotSupported { alg: String },
    #[snafu(display("Key generation error: {details}"))]
    KeyGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Network error"))]
    Network {
        #[snafu(implicit)]
        location: Location,
        source: reqwest::Error
    },
    #[snafu(display("Failed to open file {filename}"))]
    File {
        filename: String,
        #[snafu(implicit)]
        location: Location,
        source: std::io::Error,
    },
}
```

We use `#[derive(Snafu, DebugError)]` to implement the `Debug` trait that is responsible for showing a chain of errors in
the following way:

```
VC error at src/vc/oid4vci/holder.rs:751:23
 Cause: VC error at src/vc/oid4vci/holder.rs:747:23
 Cause: DID error at src/vc/oid4vci/holder.rs:743:23
 Cause: Key mismatch
```

In cases when an error includes:

1) `source` then the source error will be shown as a part of `Cause: ` line.
2) `location` then location of the error will be shown after `at` in addition to display.
