# equs-common-macros

Derive macros used by the [EQUS Credentials SDK](https://github.com/equs-ai/equs-credentials-sdk).

The crate exposes one derive, `DebugError`, which implements `Debug` for a
`snafu` error enum so that `{:?}` prints the error, the `#[snafu(implicit)]
location` of each level, and the full source chain:

```rust
use common_macros::DebugError;
use snafu::{Location, Snafu};

#[derive(Snafu, DebugError)]
enum VcError {
    #[snafu(display("VC error"))]
    Issue {
        #[snafu(implicit)]
        location: Location,
        source: DidError,
    },
}
```

Licensed under Apache-2.0.
