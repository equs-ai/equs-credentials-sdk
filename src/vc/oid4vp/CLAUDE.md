# oid4vp — Context

## Purpose
Implements the OpenID for Verifiable Presentations (OID4VP) protocol layer, providing `Holder` and `Verifier` trait definitions along with their concrete service implementations. The module covers authorization request resolution, credential discovery and presentation (auto and manual), authorization response construction and submission (plain, JWE-encrypted, and Digital Credentials API modes), transaction data handling, and full VP verification including nonce and signature checks.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root: declares sub-modules, re-exports `HolderBuilder`, `VerifierBuilder`, `ProtocolError`, `InternalError`, `ErrorType`, `BuilderError`, and all `api::*` types. |
| `api.rs` | Public trait definitions (`Holder`, `Verifier`) and all shared data types: `ResolvedAuthRequest`, `PresentationSession`, `PresentationResult`, `AuthorizationResponseObject`, `AuthorizationResponse`, `AuthorizationResponseMetadata`, `AuthorizationRequestMetadata`, `AuthResponseOptions`, `CredentialVerificationMetadata`, `CredentialsMapping`, `CredentialMapping`, `FindVCsFailReason`, `IdTokenMetadata`, and protocol-level type aliases wrapping `openid4vp` crate types. Also exposes ungated `as_delegate` and `has_delegate_request` accessors for transaction-data introspection. Also exposes (gated on `delegate-sd-jwt`) the `DelegationRequest` struct and `delegate_transaction_data_item` builder. |
| `delegate.rs` | Wire constants (`TRANSACTION_TYPE_DELEGATE`, `FORMAT_DSD_JWT`, `FORMAT_DSD_JWT_KB`, `CLAIM_DELEGATE_PAYLOAD`) + re-exports of upstream `openid4vp` delegate types. Compiled only with the `delegate-sd-jwt` feature. |
| `verifier.rs` | `VerifierService<KH, KMS, NG, HC>` — concrete `Verifier` implementation: builds signed authorization request objects (by value or by reference), generates nonces, verifies VP tokens across SD-JWT and JSON-LD formats, validates transaction data hashes, handles JWE-encrypted responses and DC API response modes. |
| `holder.rs` | `HolderService<HL, HC>` — concrete `Holder` implementation: fetches and validates authorization requests, discovers credentials via Presentation Exchange or DCQL, builds and submits authorization responses (including SIOP ID tokens), and reports credential status. |
| `builder.rs` | `VerifierBuilder` and `HolderBuilder` — fluent builders; `VerifierBuilder` accepts KMS, nonce generator, key metadata, and optional DID resolver / client metadata; `HolderBuilder` accepts KMS, vault, optional JWE decryptor, and DID resolver. |
| `jwe.rs` | `JweDecrypt` trait and `JweEncryptor` — JWE encryption of authorization responses using ECDH-ES and RSA key-wrap algorithms; `Algorithm` enum and `JwkConfig` for key negotiation. |
| `jwe_utils.rs` | Internal helpers for JWE: extracting private key handles from KMS and populating JWK sets with both public and private key material. |
| `signer.rs` | `Signer<S>` — bridges `crate::crypto::SigningKey` to the `openid4vp::signer::Signer` trait so the verifier can sign authorization request JWTs. |
| `metadata.rs` | `default_client_metadata()` and `default_wallet_metadata()` — hard-coded default `ClientMetadata` and `WalletMetadata` advertising supported VP formats (dc+sd-jwt with EdDSA / ES256). |
| `protocol_error.rs` | `ProtocolError`, `ErrorType` (re-exported from `openid4vp::core::error`) — standard-defined error responses for the presentation flow. |
| `internal_error.rs` | `InternalError` — non-protocol unexpected errors (authorization response parsing, JWE, KMS, VC verification, nonce generation, DCQL, Presentation Exchange, HTTP, ID token, etc.). |
| `tests.rs` | Integration-level unit tests for holder and verifier flows (`#[cfg(test)]`). |

## Key types / traits
- `Holder` — async trait: `get_authorization_request`, `present_credentials_auto`, `find_vcs_for_presentation`, `present_credentials`, `decline_authorization_request`, `get_credential_status`. With `delegate-sd-jwt` on, `present_credentials(_auto)` transparently produce a dSD-JWT (no holder binding) for any credential whose presentation input is targeted by a `delegate` transaction-data item — there is no separate `grant_delegation` method; the decision lives per-credential in `create_presentation_by_input`. A `delegate` item may only target dc+sd-jwt credentials; this is validated up front in `validate_transaction_data` (run while resolving the request in `get_authorization_request`), with the core `create_delegated_credential` format check as the safety net.
- `Verifier` — async trait: `create_authorization_request`, `verify_presentation`, and `verify_and_extract_presentation` (verifies like `verify_presentation` but also returns the raw presentations per credential id, so a Delegate Holder can store a returned dSD-JWT grant). A dSD-JWT grant is Holder-signed (proof of possession) and carries the request `aud`/`nonce` in its delegate payload, so it verifies through the normal path — there is no delegate-specific verify method.
- `HolderBuilder` / `VerifierBuilder` — async `build()` returns `impl Holder` / `impl Verifier`.
- `ResolvedAuthRequest` — complete parsed authorization request: client ID, metadata, presentation query, nonce, response type/mode, transaction data.
- `PresentationSession` — state kept by the verifier between request creation and response verification (nonce, resolved query, optional auth-request JWT).
- `PresentationResult` — `AuthorizationResponse(AuthorizationResponse)` | `RedirectUri(Url)` | `Presented`.
- `AuthorizationResponse` — `Plain(AuthorizationResponseObject)` | `Jwe(String)`.
- `JweDecrypt` — optional trait implemented by KMS to enable JWE-encrypted response modes.
- `ProtocolError` / `InternalError` — two-tier error split following 4xx/5xx convention.

## Dependencies
- Depends on: `crate::vc::core` (inner `Holder`, `Verifier`, `HolderService`, `VerifierService`), `crate::vc::claims`, `crate::vc::dcql`, `crate::vc::presentation_exchange`, `crate::vc::formats`, `crate::kms`, `crate::vault`, `crate::http`, `crate::nonce`, `crate::did::universal`, `crate::reqwest`, `openid4vp` crate, `one_core_asdk` (JWE utilities), `ssi`
- Used by: `crate::vc::mod` (re-exports), wrapper targets (Node.js, WASM, UniFFI)

## Constraints
- Trait objects use `#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]` for WASM compatibility.
- `jwe.rs` and `jwe_utils.rs` depend on `one_core_asdk::one_crypto::jwe` for JWE construction and decryption.
- `JweDecrypt` is an optional capability: it must be implemented by the KMS only when encrypted response modes are needed; `VerifierBuilder` requires `KMS: Kms<KH> + JweDecrypt<KH>`.
