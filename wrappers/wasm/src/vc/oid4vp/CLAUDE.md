# vc/oid4vp — Context

## Purpose
Exposes the OID4VP (OpenID for Verifiable Presentations) protocol layer to JavaScript/TypeScript via wasm-bindgen. Provides the `OID4VPHolder` WASM class for the full credential presentation flow, a builder (`OID4VPHolderBuilder`), and opaque JS types for authorization requests, presentation results, credential mappings, and VC status.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared OID4VP types: opaque extern JS types `ClientMetadata`, `PresentationDefinition`, `AuthorizationResponseMetadata`, `RustAuthorizationRequest` (mapped to `CommonAuthorizationRequest` TS type), `CredentialMapping`, `CredentialsMapping`, `WalletMetadata`, `AuthorizationRequest` (with `getAuthRequest` getter and `new` constructor), `PresentationResult`, `VCStatus`. |
| `holder.rs` | `OID4VPHolder` — wasm_bindgen async class wrapping `Box<dyn Holder>`. Exposes `getAuthorizationRequest`, `presentCredentialsAuto`, `findVcsForPresentation`, `presentCredentials`, `declineAuthorizationRequest`, and `getCredentialStatus`. Defines internal helpers: `JsPresentationResult` / `PresentationResultType` (serde-based enums for serializing results to JS), `JsVCStatus` / `JsVCStatusFormat` / `TslVcStatusType` (for VC status format bridging), and conversion helpers `convert_to_js_credentials_mapping` and `convert_hash_map_of_credentials_to_js_object`. |
| `builder.rs` | `OID4VPHolderBuilder` — wasm_bindgen builder for `OID4VPHolder`. Constructor takes `Kms`, `Vault`, `client_id`, and `ReqwestHttpClient`. Chainable methods: `withDidResolver`, `withWalletMetadata`, `withNonceHandler`. Async `build()` produces `OID4VPHolder`. |

## Key types / traits
- `OID4VPHolder` — WASM async class for the full OID4VP presentation flow.
- `OID4VPHolderBuilder` — WASM builder; wires `JsKms`, `JsVault`, `JsDIDResolver`, `JsNonceHandler`, and `ReqwestHttpClient` together.
- `AuthorizationRequest` — opaque JS type wrapping a `CommonAuthorizationRequest`; provides `getAuthRequest()` accessor for Rust-side deserialization.
- `PresentationResult` — opaque JS type for the three possible presentation outcomes (AuthorizationResponse, RedirectUri, Presented).
- `CredentialsMapping` / `CredentialMapping` — opaque JS types for the map of credentials required for presentation.
- `VCStatus` — opaque JS type carrying the resolved credential status.

## Dependencies
- Depends on: `agent_sdk::vc::oid4vp`, `crate::did::resolver`, `crate::http::ReqwestHttpClient`, `crate::kms`, `crate::nonce`, `crate::vault`, `crate::vc` (credential/find-result types)
- Used by: WASM browser consumer TypeScript code

## Constraints
- All async impls use `#[async_trait(?Send)]`.
- `AuthorizationRequest` is an opaque JS class with a `getAuthRequest()` method; Rust accesses the inner `CommonAuthorizationRequest` by calling this getter and deserializing with `serde_wasm_bindgen`.
- `CredentialsMapping` (a `HashMap<String, CredentialsFindResult>`) is converted to a `JsValue` object via `js_sys::Object` + `Reflect::set`, not plain serde serialization.
