# did — Context

## Purpose
Exposes DID method utilities and a universal DID resolver to Node.js via NAPI-RS. Provides NAPI classes for `did:key`, `did:peer`, `did:web`, and `did:webvh` generation/resolution, plus the `_UniversalDIDResolver` class that dispatches resolution to built-in or caller-supplied custom resolvers.

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines `JsUniversalDIDResolver`, `JsDIDResolver` (callback-based custom resolver), `JsVerificationMethodKey`, `JsResolutionOptions`, `JsResolutionOutput`, and related metadata structs. Bridges JS promise callbacks into the `DIDResolver` async trait. |
| `key.rs` | `JsDIDKey` NAPI class — wraps `DIDKey::generate` to produce a `did:key` string from a `JsKeyHandle`. |
| `peer.rs` | `JsDIDPeer` NAPI class — wraps `DIDPeer::generate_did_peer4` to create a `did:peer` (method 4) from verification keys and services. |
| `web.rs` | `JsDIDWeb` NAPI class — wraps `DIDWeb::generate_did_from_url` and `DIDWeb::generate_did_document`. |
| `webvh.rs` | `JsDIDWebVh` NAPI class — wraps `DIDWebVh` resolver for `did:webvh` resolution, requiring an HTTP client. |

## Key types / traits
- `JsUniversalDIDResolver` — NAPI object wrapping `UniversalResolver`; supports `resolve`, `resolve_verification_method`, and `add_resolver`.
- `JsDIDResolver` — NAPI object exposing a JS callback as a `DIDResolver` trait implementation (ThreadsafeFunction).
- `JsVerificationMethodKey` — Pairs a `JsKeyHandle` with a set of `JsVerificationRelationshipType` values.
- `JsDIDKey`, `JsDIDPeer`, `JsDIDWeb`, `JsDIDWebVh` — NAPI classes for each supported DID method.

## Dependencies
- Depends on: `agent_sdk::did` (including `didkey`, `didpeer`, `didweb`, `webvh`, `universal`), `crate::http::ReqwestHttpClient`, `crate::kms::JsKeyHandle`
- Used by: `wrappers/nodejs/src/lib.rs` (re-exported module), Node.js consumers of the SDK

## Constraints
- `did:webvh` resolution requires an HTTP client and is non-wasm only in the core library; this module wraps it for Node.js use.
