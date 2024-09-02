# Overview
We use the `snafu` library for error handling, taking advantage of its features to provide more detailed and user-friendly error messages. The following guidelines ensure consistency and clarity in how errors are handled and reported in our codebase.

## Rules
- Developers should try to write more informative error messages, including relevant error details and arguments.
- Use the `#[derive(Snafu)]` macro for defining error enums or structs.
- Do not use the `#[derive(Debug)]` macro for errors. The default `Debug` implementation displays internal error structure details that are not readable enough.
- When naming error variants, avoid adding the `Error` postfix to the variant name. The context provided by the error name should be sufficient.
- If an error contains a nested source error, include a `Location` struct to capture and display where the error occurred.
- Use the `#[snafu(implicit)]` attribute for the `location` field to avoid providing it during error creation.
- Use the `ensure!` macro if you want to raise an error if some condition is not met.
- All error enums should use the `#[non_exhaustive]` macro to allow for future extensions without breaking existing code.

## Error Log Example
As shown in the example below, error logs should be structured to provide useful information to the end user:
```
Internal error at src/common/catalog/src/error.rs:80:10
 Cause: Crypto error at src/common/function/src/error.rs:90:10
  Cause: BLS12-381 algorithm is not supported
```

# Common error types
## Specific operation error
These error types should be as descriptive as possible and should not require 
additional context such as location information.

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
Describe a general error and should provide additional context, 
by providing detailed descriptions and the location where the error occurred.

```rust
#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Signature verifying error at {location}\n Cause: {details}"))]
    SignatureVerification {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[error("Key generation error at {location}\n Cause: {details}")]
    KeyGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    // Other errors     
}
```

For this type error a detailed description should be provided during creation.

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
Describe the underlying module/crate error, and should include the original source error and 
the location within the module where it occurred.

```rust
#[derive(Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Crypto error at {location}\n Cause: {source}"))]
    Crypto {
        #[snafu(implicit)]
        location: Location,
        source: crypto::Error
    },
    #[snafu(display("Network error at {location}\n Cause: {source}"))]
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
 
#[derive(Snafu)]
#[non_exhaustive]
enum Error {
    #[snafu(display("Unsupported key: {type_}"))]
    KeyNotSupported { type_: String },
    #[snafu(display("Unsupported algorithm: {alg}"))]
    AlgNotSupported { alg: String },
    #[snafu(display("Key generation error at {location}\n Cause: {details}"))]
    KeyGeneration {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Network error at {location}\n Cause: {source}"))]
    Network {
        #[snafu(implicit)]
        location: Location,
        source: reqwest::Error
    },
    #[snafu(display("Failed to open file {filename} at {location}\n {source}"))]
    File {
        filename: String,
        #[snafu(implicit)]
        location: Location,
        source: std::io::Error,
    },
}
```

We can reduce boilerplate by implementing the Debug trait for the Error type. 
By implementing Debug as shown below, we can avoid the need to provide the source explicitly in the display message.

```rust
impl std::fmt::Debug for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::write!(fmt, "{}", self)?;

        let mut error: &dyn std::error::Error = self;
        while let Some(source) = error.source() {
            write!(fmt, "\n Cause: {}", source)?;
            error = source;
        }

        Ok(())
    }
}
```
