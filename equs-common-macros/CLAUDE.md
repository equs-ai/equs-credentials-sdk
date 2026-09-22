# equs-common-macros — derive macros

Proc-macro crate. Published to crates.io as `equs-common-macros`; the lib
target is `common_macros`, so every consumer writes
`use common_macros::DebugError;`. Do not change `[lib] name` — 44 sites in
`src/` and `docs/guidelines/error_handling.md` depend on it.

| Path | Role |
|------|------|
| `src/lib.rs` | `DebugError` derive. Emits `Debug` for a `snafu` error enum: the display, the `#[snafu(implicit)] location` of each level that has one, then the source chain. |
| `tests/debug_error.rs` | Location and chain output across three nested error types. Not in the published package. |

`snafu` is a dev-dependency, not a dependency. `src/lib.rs` names
`snafu::AsErrorSource` only inside a `quote!` block, which expands at the call
site and resolves against the caller's `snafu`. Only the tests link it here.

Released independently of the SDK, on a `common-macros-X.Y.Z` tag — see
`.github/workflows/publish-common-macros.yml`. It must be on crates.io before
`equs-credentials-sdk` can publish, because a path dependency is rewritten to a
registry dependency at publish time.
