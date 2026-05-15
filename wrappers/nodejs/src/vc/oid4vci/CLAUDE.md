# vc/oid4vci — Context

## Purpose
Exposes the OID4VCI (OpenID for Verifiable Credential Issuance) protocol layer to Node.js via NAPI-RS. Provides `OID4VCIHolder` and `OID4VCIIssuer` classes for the full credential issuance flow, along with builder functions, metadata discovery, credential offer resolution, and protocol error mappings.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared OID4VCI types: `JsTokenValidation`/`JsTokenValidationEnum` (introspect vs. JWKS), `JsDuration`, `JsCredentialLifetime` (infinite/finite), `JsNotification`/`JsNotificationEvent`. |
| `holder.rs` | `OID4VCIHolder` — NAPI class (wraps any `Holder` impl via a trait object). Exposes `get_issuer_metadata`, `authz_code_flow_with_scope`, `get_access_token`, `request_credential`, `request_deferred_credential`, `verify_credential_extra`, `store_credential`, and `send_notification`. Uses ThreadsafeFunction callbacks for authorization flows. |
| `issuer.rs` | `OID4VCIIssuer` — NAPI class (wraps any `Issuer` impl). Exposes `get_issuer_metadata`, `get_cred_def_metadata`, `generate_nonce`, `create_credential_offer`, and `issue_credential`. Defines `CredentialOffer`, `NonceResponse`, `IssuanceResult`, and `IssuanceResultType`. |
| `builder.rs` | `_build_vci_holder` and `_build_vci_issuer` — async NAPI factory functions using `HolderBuilder` and `IssuerBuilder`. Handles optional token validation, clock skew, PoP metadata, dedicated keys, and HTTP client. Also defines `JsIssuerDiscovery` wrapping `IssuerDiscovery` enum. |
| `metadata.rs` | `MetadataDiscovery` — NAPI class wrapping `AsdkMetadataDiscovery`. Exposes `discover_issuer_metadata` and `discover_auth_server_metadata`. |
| `credential_offer_resolver.rs` | `OID4VCICredentialOfferResolver` — NAPI class resolving credential offer URIs to `OID4VCICredentialOffer` objects, with optional custom HTTP client. |
| `error.rs` | Maps OID4VCI `InternalError`, `ProtocolError`, and `CredentialOfferResolverError` to typed `EncodableError` codes (`JsInternalError`, `JsProtocolError`, `JsCredentialOfferResolverError`). |

## Key types / traits
- `OID4VCIHolder` — Full OID4VCI holder with auth code and pre-auth flows.
- `OID4VCIIssuer` — OID4VCI issuer supporting immediate credential issuance.
- `JsIssuerDiscovery` — Enum for discovering issuer metadata from URL, offer, or pre-fetched metadata.
- `MetadataDiscovery` — Utility for fetching issuer and auth server metadata.
- `OID4VCICredentialOfferResolver` — Resolves credential offer URIs.

## Dependencies
- Depends on: `agent_sdk::vc::oid4vci`, `crate::vc::core`, `crate::kms::JsKms`, `crate::vault::JsVault`, `crate::http::ReqwestHttpClient`, `crate::nonce::JsNonceHandler`, `crate::did::JsDIDResolver`
- Used by: Node.js OID4VCI issuer and holder integrations
