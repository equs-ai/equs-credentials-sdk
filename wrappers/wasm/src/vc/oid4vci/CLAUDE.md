# vc/oid4vci — Context

## Purpose
Exposes the OID4VCI (OpenID for Verifiable Credential Issuance) protocol layer to JavaScript/TypeScript via wasm-bindgen. Provides the `OID4VCIHolder` WASM class for the full credential issuance flow (auth code and pre-auth code), a builder for constructing it (`OID4VCIHolderBuilder`), and supporting utilities for issuer discovery, credential offer resolution, and metadata discovery.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared OID4VCI types: opaque extern JS types `OID4VCIIssuerMetadata`, `TokenResponse`, `OID4VCICredentialOffer`, `CredentialResponse`. Provides `TryFrom<CredentialResponseResolved> for CredentialResponse` — converts immediate (credential) or deferred (transaction_id + interval) SDK results into the JS-side opaque `CredentialResponse` object. |
| `holder.rs` | `OID4VCIHolder` — wasm_bindgen async class wrapping a boxed `dyn Holder` (via `_HolderWrapper`). Exposes `getIssuerMetadata`, `authzCodeFlowWithScope`, `getAccessToken`, `requestCredential`, `requestDeferredCredential`, `verifyCredentialExtra`, `storeCredential`, and `sendNotification`. Declares JS callback types `AuthCodeCallback` and `AuthCallback` (via `#[wasm_bindgen(typescript_custom_section)]`). Also defines `CredentialExtraVerification` wasm enum (`CredentialIssuerIdentifier` variant). |
| `builder.rs` | `OID4VCIHolderBuilder` — wasm_bindgen builder for `OID4VCIHolder`. Constructor takes `Kms`, `Vault`, `client_id`, `IssuerDiscovery`, and `ReqwestHttpClient`. Chainable methods: `withRedirectUrl`, `withDidResolver`, `withPop`, `withCredentialExtraVerification`. `IssuerDiscovery` wasm class with `fromUrl`, `fromOffer`, and `fromMetadata` constructors. `ProofOfPossessionMetadataBuilder` and `ProofOfPossessionNotBefore` wasm classes for configuring PoP parameters. |
| `metadata.rs` | `MetadataDiscovery` — wasm_bindgen struct. Exposes `discoverIssuerMetadata` and `discoverAuthServerMetadata` for fetching OID4VCI issuer and authorization server metadata. |
| `credential_offer_resolver.rs` | `OID4VCICredentialOfferResolver` — wasm_bindgen struct. Resolves `OID4VCICredentialOffer` from a credential offer URI; constructors `new()` and `withHttpClient(http_client)`. Exposes async `resolve(offer_uri)`. |

## Key types / traits
- `OID4VCIHolder` — WASM async class for the full OID4VCI issuance flow.
- `OID4VCIHolderBuilder` — WASM builder; wires `JsKms`, `JsVault`, `JsDIDResolver`, `ReqwestHttpClient`, and PoP options together.
- `IssuerDiscovery` — WASM class encapsulating three discovery modes: by URL, by credential offer, or by pre-fetched metadata.
- `AuthCodeCallback` / `AuthCallback` — TypeScript function types for the authorization code and pre-auth code flows.
- `CredentialExtraVerification` — WASM enum for optional post-issuance verification steps.
- `ProofOfPossessionMetadataBuilder` / `ProofOfPossessionNotBefore` — WASM builder types for PoP JWT generation parameters.

## Dependencies
- Depends on: `agent_sdk::vc::oid4vci`, `agent_sdk::vc::core::ProofOfPossessionMetadata`, `crate::did::resolver`, `crate::http::ReqwestHttpClient`, `crate::kms`, `crate::vault`, `crate::vc` (credential types)
- Used by: WASM browser consumer TypeScript code

## Constraints
- All async impls use `#[async_trait(?Send)]`; JS callbacks are bridged via `wasm_bindgen_futures::JsFuture`.
- Opaque JS types (`OID4VCIIssuerMetadata`, `TokenResponse`, etc.) are passed across the FFI boundary without deserialization in the hot path; conversion uses `serde_wasm_bindgen` + `Serializer::json_compatible()`.
