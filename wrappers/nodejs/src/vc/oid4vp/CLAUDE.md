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
| `error.rs` | Maps OID4VP `InternalError` and `ProtocolError` to typed `EncodableError` codes (`JsInternalError` with ~25 variants, `JsProtocolError` with ~13 variants). |

## Key types / traits
- `InnerOID4VPHolder` — OID4VP holder handling the full presentation flow.
- `InternalOID4VPVerifier` — OID4VP verifier for creating authorization requests and verifying presentations.
- `ClientId` — NAPI class constructing an OID4VP client identifier from a string, DID, or redirect URI.
- `_AuthorizationRequest` — NAPI record representing the resolved authorization request exchanged between holder and verifier.
- `JsPresentationSession` — Session nonce and resolved presentation query, returned alongside an authorization request.

## Dependencies
- Depends on: `agent_sdk::vc::oid4vp`, `crate::vc::core`, `crate::vault`, `crate::kms::JsKms`, `crate::vault::JsVault`, `crate::nonce::JsNonceHandler`, `crate::http::ReqwestHttpClient`, `crate::did::JsDIDResolver`
- Used by: Node.js OID4VP verifier and holder integrations
