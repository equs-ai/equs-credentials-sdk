# wasm — Context

## Purpose
Houses the WASM-target HTTP client (`WasmClient`) that drives `reqwest::Client` within a browser or WASM runtime, applying content-size and content-type validation inline (without middleware).

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines `WasmClient` and its `async_call` implementation; enforces HTTPS-only policy, request body size warnings, and response validation. |

## Key types / traits
- `WasmClient` — concrete struct holding a `reqwest::Client`, `ContentSizeLimiter`, `ContentTypeValidator`, and an `insecure` flag; implements the `async_call` contract expected by `ReqwestClient`.

## Dependencies
- Depends on: `crate::reqwest::validators`, `crate::http`, `oauth2` HTTP types, `reqwest`.
- Used by: `crate::reqwest::ReqwestClient` when compiled for `target_arch = "wasm32"`.

## Constraints
- Wasm32 only; the non-wasm path uses `reqwest_middleware` with `ValidatorMiddleware` instead.
