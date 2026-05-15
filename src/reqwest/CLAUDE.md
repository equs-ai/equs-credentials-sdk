# reqwest — Context

## Purpose
Provides the SDK's concrete HTTP transport layer by wrapping the `reqwest` crate into a `ReqwestClient` that implements `crate::http::HttpClient`. It enforces TLS-only connections (configurable), optional body-size limits, content-type header validation, tracing, and `Set-Cookie` header removal.

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines `ReqwestClient`, implements `HttpClient::async_call` for both non-wasm and wasm targets, and houses integration tests. |
| `builder.rs` | `ReqwestClientBuilder` — fluent builder for `ReqwestClient`; configures TLS, size limits, trusted root certificates, and insecure mode. |
| `middleware.rs` | `ValidatorMiddleware` — `reqwest_middleware` layer that validates sizes and content types, and strips `Set-Cookie` headers (non-wasm only). |
| `validators/` | Sub-module providing `ContentSizeLimiter` and `ContentTypeValidator` used by both the middleware and the WASM client. |
| `wasm/` | `WasmClient` — inline (no middleware) HTTP client implementation for the wasm32 target. |

## Key types / traits
- `ReqwestClient` — the public HTTP client; implements `crate::http::HttpClient`.
- `ReqwestClientBuilder` — constructs a `ReqwestClient`; exposes `with_response_content_size_limit`, `with_request_content_size_limit`, `add_trusted_root_certificate`, `insecure`, and `build`.
- `ValidatorMiddleware` — non-wasm `reqwest_middleware::Middleware` for payload validation.
- `Certificate` — re-export of `reqwest::Certificate` (non-wasm only).

## Dependencies
- Depends on: `crate::http` (`HttpClient`, `HttpError`), `crate::reqwest::validators`, `crate::reqwest::wasm`, `reqwest`, `reqwest_middleware`, `reqwest_tracing`, `oauth2`.
- Used by: consumers of `crate::http::HttpClient` throughout the SDK (VC, DID, DIDComm modules).

## Constraints
- Middleware path (`ValidatorMiddleware`, `reqwest_middleware`) is non-wasm only.
- WASM path delegates to `wasm::WasmClient`; `add_trusted_root_certificate` is `#[cfg(debug_assertions)]` and non-wasm only.
- Default TLS: HTTPS-only, TLS 1.2 minimum, no redirect following, Rustls backend.
