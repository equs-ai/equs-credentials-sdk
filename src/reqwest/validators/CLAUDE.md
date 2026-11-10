# validators — Context

## Purpose
Provides response and request payload validation for the reqwest-based HTTP client: enforces body-size limits and verifies that response `Content-Type` headers are allowed and match the request's `Accept` header.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; declares `HttpPayloadError` enum used by both validators. |
| `content_size.rs` | `ContentSizeLimiter` — configures optional byte-size ceilings for request and response bodies; checks the `Content-Length` header, and `read_response_body` streams the body for both the middleware and `WasmClient`, failing at the first chunk over the limit. |
| `content_type.rs` | `ContentTypeValidator` — checks that the response `Content-Type` is in the allowed MIME-type allowlist and matches the request `Accept` header; validates JSON/form-urlencoded body structure. |

## Key types / traits
- `ContentSizeLimiter` — builder-style struct; call `unlimited()`, then `with_response_size_limit` / `with_request_size_limit`.
- `ContentTypeValidator` — unit struct with `resolve_request_content_type` and `validate_response_content_type`.
- `HttpPayloadError` — snafu error enum with `ContentType` and `ContentSize` variants.

## Dependencies
- Depends on: `crate::utils::http` (MIME type constants), `reqwest`, `mime`, `snafu`.
- Used by: `crate::reqwest::middleware::ValidatorMiddleware` (non-wasm), `crate::reqwest::wasm::WasmClient` (wasm).

## Constraints
- All items are wasm-compatible; `read_response_body` needs reqwest's `stream` feature.
