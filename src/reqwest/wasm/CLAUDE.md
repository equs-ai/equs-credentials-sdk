# wasm — Context

## Purpose
Houses the WASM-target HTTP client (`WasmClient`) that drives `reqwest::Client` within a browser or WASM runtime, applying content-size and content-type validation inline (without middleware).

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines `WasmClient` and its `async_call` implementation; enforces HTTPS-only policy, request body size warnings, and response validation. Streams the response body through `ContentSizeLimiter::read_limited_body`; HEAD and CONNECT requests and statuses 101, 103, 204, 205 and 304 get an empty body, because Fetch gives them no body stream and reqwest's wasm `bytes_stream` panics without one. |

## Key types / traits
- `WasmClient` — concrete struct holding a `reqwest::Client`, `ContentSizeLimiter`, `ContentTypeValidator`, and an `insecure` flag; implements the `async_call` contract expected by `ReqwestClient`.

## Dependencies
- Depends on: `crate::reqwest::validators`, `crate::http`, `oauth2` HTTP types, `reqwest` (`stream` feature), `futures`.
- Used by: `crate::reqwest::ReqwestClient` when compiled for `target_arch = "wasm32"`.

## Constraints
- Used on wasm32 only; the non-wasm path uses `reqwest_middleware` with `ValidatorMiddleware` instead. It compiles on every target, so its tests run natively against reqwest's native backend.
