# oid4vci — Context

## Purpose
Implements the OpenID for Verifiable Credential Issuance (OID4VCI) protocol layer, providing `Issuer` and `Holder` trait definitions along with their concrete service implementations. The module covers credential offer creation, token authorization (auth-code and pre-authorized-code flows), nonce generation and validation, immediate and deferred credential issuance, access-token validation, and credential storage on the holder side.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root: declares sub-modules, re-exports public types including `HolderBuilder`, `IssuerBuilder`, `IssuerDiscovery`, `CredentialOfferResolver`, `ProtocolError`, `InternalError`, and all `api::*` types. |
| `api.rs` | Public trait definitions (`Issuer`, `Holder`) and all shared data types: `IssuerMetadata`, `CredentialOffer*`, `TokenRequest/Response`, `CredentialRequest/Response`, `CredentialResult`, `AuthzFlow`, `CredentialLifetime`, `CredentialExtraVerification`, `Error`, `Result`. |
| `issuer.rs` | `IssuerService<IS, HC, NH>` — concrete `Issuer` implementation: validates access tokens, resolves credential definitions, validates scope and claim names, handles batch issuance and nonce lifecycle. |
| `holder.rs` | `HolderService<HL, HC>` — concrete `Holder` implementation: discovers issuer metadata, executes auth-code / pre-auth-code flows, requests and defers credentials, verifies issued credentials. |
| `builder.rs` | `IssuerBuilder` and `HolderBuilder` — fluent builders for constructing `Issuer` and `Holder` instances; `IssuerDiscovery` enum (by URL, offer, or direct metadata); `ProofOfPossessionMetadataBuilder`. |
| `metadata.rs` | `IssuerMetadata` / `CredentialMetadata` type aliases (wrapping `oid4vci` crate types); `convert_metadata` — maps public `IssuerMetadata` to the internal `vc::core::IssuerMetadata` used by `IssuerService`. |
| `credential_offer_resolver.rs` | `CredentialOfferResolver<HC>` — resolves a `credential_offer_uri` link to a `CredentialOfferParams` via HTTP fetch. |
| `credential_issuer_identifier.rs` | `CredentialIssuerIdentifier` enum — parses the issuer identifier from a credential into DID, OID4VCI URL, or Other form; used for `CredentialExtraVerification::CredentialIssuerIdentifier`. |
| `token_validation.rs` | `Introspect<HC>` and `ByJwks<HC>` — two strategies for validating access tokens: OAuth2 introspection endpoint or JWKS signature verification. |
| `protocol_error.rs` | `ProtocolError`, `ErrorType`, `CredentialEndpointError`, `TokenEndpointError`, `CredentialOfferEndpointError` — standard-defined error types mapped from `oid4vci` crate errors. |
| `internal_error.rs` | `InternalError` — non-protocol unexpected errors (parse, vault, KMS, discovery, HTTP, nonce handler, type conversion, etc.). |
| `tests.rs` | Shared test fixtures (`SampleIssuerMetadata`, `SampleCredentialRequest`, sample claims, mock nonce handler, JWT/JWKS samples) used across intra-module tests. |

## Key types / traits
- `Issuer` — async trait: `get_issuer_metadata`, `get_cred_def_metadata`, `generate_nonce`, `create_credential_offer`, `issue_credential`.
- `Holder` — async trait: `get_issuer_metadata`, `authz_code_flow_with_scope`, `get_access_token`, `request_credential`, `request_deferred_credential`, `verify_credential_extra`, `store_credential`, `send_notification`.
- `IssuerBuilder` / `HolderBuilder` — async `build()` returns `impl Issuer` / `impl Holder`.
- `IssuerDiscovery` — `Url(String)` | `Offer(CredentialOfferParams)` | `Metadata(IssuerMetadata, AuthorizationMetadata)`.
- `CredentialLifetime` — `Infinite` | `Finite(time::Duration)`; defaults to `DEFAULT_CRED_LIFETIME_DAYS`.
- `CredentialExtraVerification` — `CredentialIssuerIdentifier` post-issuance check.
- `CredentialResult` — `Deferred { transaction_id, interval }` | `Credential { credentials, notification_id }`.
- `ProtocolError` / `InternalError` — two-tier error split following 4xx/5xx convention.

## Dependencies
- Depends on: `crate::vc::core` (inner `Issuer`, `Holder`, `IssuerService`, `HolderService`, `KeyMetadata`), `crate::vc::pop`, `crate::vc::claims`, `crate::vc::formats`, `crate::kms`, `crate::vault`, `crate::http`, `crate::nonce`, `crate::did::universal`, `crate::reqwest`, `oid4vci` crate, `oauth2`, `openidconnect`, `ssi`
- Used by: `crate::vc::mod` (re-exports), wrapper targets (Node.js, WASM, UniFFI)

## Constraints
- Trait objects use `#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]` so the module compiles on both native and WASM targets.
- `HolderBuilder::new` uses an `Arc<HC>` so the same HTTP client can be shared with the internal `UniversalResolver`.
