# vc/oid4vp — Context

## Purpose
Exposes the OID4VP (OpenID for Verifiable Presentations) protocol layer to Node.js via NAPI-RS. Provides `InnerOID4VPHolder` and `InternalOID4VPVerifier` classes for the full credential presentation flow, including authorization request creation, credential selection, presentation, and verification.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared OID4VP types: `JsPresentationResult`, `PresentationResultType`, `JsAuthorizationResponseType`, `JsInnerAuthorizationResponse`, `JsAuthorizationResponseObject`, `JsTransactionDataResponse`, and `ClientId` NAPI class (from DID or redirect URI). |
| `holder.rs` | `InnerOID4VPHolder` — NAPI class wrapping `Box<dyn Holder>`. Exposes `get_authorization_request`, `present_credentials_auto`, `find_vcs_for_presentation`, `present_credentials`, `decline_authorization_request`, and `get_credential_status`. Defines `_AuthorizationRequest` (resolved auth request as NAPI object) and `JsAuthorizationResponseMetadata`. |
| `verifier.rs` | `InternalOID4VPVerifier` — NAPI class wrapping `Box<dyn Verifier>`. Exposes `create_authorization_request`, `verify_presentation`, and `verify_and_extract_presentation` (verify + return the raw presentations per credential id via `JsVerifiedPresentation`, so a Delegate Holder can store a returned dSD-JWT grant). Defines `JsAuthResponseOptions`, `JsPassAuthRequestObject`, `JsAuthorizationRequestMetadata`, `JsCredentialVerificationMetadata`, `JsPresentationSession`, `JsVerifiedPresentation`, `AuthorizationRequestWithSession`, and `JsHttpMethodForAuth`. |
| `builder.rs` | `_build_vp_verifier` and `_build_vp_holder` — async NAPI factory functions using `VerifierBuilder` and `HolderBuilder`. Supports optional client metadata, DID resolver, HTTP client, nonce handler, wallet metadata, PoP metadata, and trusted root certificates. |
| `delegate.rs` | EXPERIMENTAL, compiled only with `delegate-sd-jwt`. dSD-JWT delegation bindings: `buildDelegateTransactionData` (wraps `agent_sdk`'s `delegate_transaction_data_item` — salt generation + Array Disclosure encoding stay in Rust). Its `request` parameter is a raw `JsonObject` deserialized into the internal `JsDelegationRequest` enum, but exposes the hand-written `DelegationRequest` union type (`wrappers/nodejs/types/vc/oid4vp/delegation-request.ts` — Node.js-only, since the wasm wrapper doesn't support `delegate-sd-jwt`) via `ts_arg_type`. |
| `error.rs` | Maps OID4VP `InternalError` and `ProtocolError` to typed `EncodableError` codes (`JsInternalError` with ~25 variants, `JsProtocolError` with ~13 variants). |

## Key types / traits
- `InnerOID4VPHolder` — OID4VP holder handling the full presentation flow.
- `InternalOID4VPVerifier` — OID4VP verifier for creating authorization requests and verifying presentations.
- `ClientId` — NAPI class constructing an OID4VP client identifier from a string, DID, or redirect URI.
- `_AuthorizationRequest` — NAPI record representing the resolved authorization request exchanged between holder and verifier.
- `JsPresentationSession` — Session nonce and resolved presentation query, returned alongside an authorization request.
- `JsDelegationRequest` — internal serde-tagged enum (`#[serde(tag = "format")]`) that `buildDelegateTransactionData` deserializes its raw `JsonObject` argument into: `Open { credential_ids, payload_claims }` for `"dSD-JWT"`, `HolderBinding { credential_ids, delegate_cnf, payload_claims }` for `"dSD-JWT+KB"`. Mirrors `agent_sdk::DelegationRequest::open`/`::holder_binding` — `delegateCnf` is required by the JSON shape itself for `HolderBinding` and absent from `Open`, so a malformed request fails to deserialize before any business-rule validation runs. The TS-facing shape is the hand-written `DelegationRequest` union in `wrappers/nodejs/types/vc/oid4vp/delegation-request.ts` (`OpenDelegationRequest | HolderBindingDelegationRequest`) — kept out of the shared `wrappers/types/` because the wasm wrapper doesn't support `delegate-sd-jwt` — wired in via `ts_arg_type` + `scripts/add-import-line.mjs`. That same file also exports a runtime `DelegationRequest` *value* (a plain object, not a class) alongside the type of the same name — TS resolves each in its own namespace — with `.open(credentialIds, payloadClaims?)` / `.holderBinding(credentialIds, delegateCnf, payloadClaims?)` factories mirroring the Rust constructors, so callers never have to spell the `"dSD-JWT"` / `"dSD-JWT+KB"` wire literals themselves.

## Constraints
- Any binding that takes a `JsNonceHandler` receives `generate`/`validate` as bare functions with no receiver, so a **NAPI class instance** (e.g. `new LocalNonceHandler()`) must be wrapped with the TS `contextEnsuredNonceHandler` helper first — otherwise the unbound prototype method raises `TypeError: Illegal invocation` inside the ThreadsafeFunction callback and **aborts the process** (not a catchable throw). The `OID4VPVerifierBuilder` / `OID4VPHolderBuilder` TS classes apply it for callers; `buildDelegateTransactionData` is a raw NAPI export, so its callers must apply it themselves. Plain object literals (`{ generate, validate }`) need no wrapping.

## Dependencies
- Depends on: `agent_sdk::vc::oid4vp`, `crate::vc::core`, `crate::vault`, `crate::kms::JsKms`, `crate::vault::JsVault`, `crate::nonce::JsNonceHandler`, `crate::http::ReqwestHttpClient`, `crate::did::JsDIDResolver`
- Used by: Node.js OID4VP verifier and holder integrations
