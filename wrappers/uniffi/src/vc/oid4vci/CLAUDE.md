# vc/oid4vci — Context

## Purpose
Exposes the OID4VCI (OpenID for Verifiable Credential Issuance) protocol layer to Kotlin and Swift via UniFFI. Provides the `OID4VCIHolder` UniFFI object for the full credential issuance flow (auth code and pre-auth code), along with supporting types for token responses, credential results, PoP metadata, and authorization callbacks.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared OID4VCI types: `CredentialResultEnum`/`CredentialResult` custom type, `TokenResponseData`/`TokenResponse` custom type, `ProofOfPossessionNotBefore` enum, `ProofOfPossessionMetadataBuilder` UniFFI object, `CredentialExtraVerification` enum, `AuthzFlow` enum. Defines `CredentialResponse` and `TokenResponse` remote records. |
| `holder.rs` | `OID4VCIHolder` — UniFFI object (async_runtime = tokio) wrapping any `agent_sdk::vc::oid4vci::Holder` impl via trait object. Exposes `get_issuer_metadata`, `authz_code_flow_with_scope`, `get_access_token`, `request_credential`, `request_deferred_credential`, `verify_credential_extra`, `store_credential`, and `send_notification`. Defines `AuthCodeCallback` and `AuthCallback` foreign traits for authorization flows. Also defines `Notification`/`NotificationEvent`. |
| `builder.rs` | Builder function for constructing `OID4VCIHolder` with issuer discovery, HTTP client, PoP, extra verification options, and optional DID resolver. |
| `metadata.rs` | Metadata discovery utilities for fetching OID4VCI issuer and authorization server metadata. |
| `credential_offer_resolver.rs` | Credential offer URI resolver producing `OID4VCICredentialOffer` objects. |

## Key types / traits
- `OID4VCIHolder` — UniFFI async object for the full OID4VCI issuance flow.
- `AuthCodeCallback`, `AuthCallback` — UniFFI foreign traits for authorization user interactions.
- `ProofOfPossessionMetadataBuilder` — Builder object for configuring PoP lifetime and not-before strategy.
- `TokenResponse`, `CredentialResponse` — UniFFI records for protocol responses.

## Dependencies
- Depends on: `agent_sdk::vc::oid4vci`, `agent_sdk::vc::core::ProofOfPossessionMetadata`, `crate::common`, `crate::vc` (credential types), `crate::kms`, `crate::vault`
- Used by: Kotlin/Swift OID4VCI holder integrations
