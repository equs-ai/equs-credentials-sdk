# oid4vci — Context

## Purpose
Implements the OpenID for Verifiable Credential Issuance (OID4VCI) protocol layer, providing `Issuer` and `Holder` trait definitions along with their concrete service implementations. The module covers credential offer creation, token authorization (auth-code and pre-authorized-code flows), nonce generation and validation, immediate and deferred credential issuance, access-token validation, and credential storage on the holder side.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root: declares sub-modules, re-exports public types including `HolderBuilder`, `IssuerBuilder`, `IssuerDiscovery`, `CredentialOfferResolver`, `ProtocolError`, `InternalError`, and all `api::*` types. |
| `api.rs` | Public trait definitions (`Issuer`, `Holder`) and all shared data types: `IssuerMetadata`, `CredentialOffer*`, `TokenRequest/Response`, `CredentialRequest/Response`, `CredentialResult`, `AuthzFlow`, `CredentialLifetime`, `CredentialExtraVerification`, `Error`, `Result`. |
| `issuer.rs` | `IssuerService<IS, HC>` — concrete `Issuer` implementation: validates access tokens, resolves credential definitions, validates scope and claim names, handles batch issuance and nonce lifecycle. |
| `holder.rs` | `HolderService<HL, HC>` — concrete `Holder` implementation: discovers issuer metadata, executes auth-code / pre-auth-code flows, requests and defers credentials, verifies issued credentials. |
| `auth_server_selection.rs` | Picks the authorization server a holder binds to and exchanges a pre-authorized code at: `AuthServerHint`, `AuthServerChoice`, `select_authorization_server`, `listed_offered_server`, `discover_first_supporting_authorization_code`. |
| `builder.rs` | `IssuerBuilder` and `HolderBuilder` — fluent builders for constructing `Issuer` and `Holder` instances; `IssuerDiscovery` enum (by URL, offer, or direct metadata); `ProofOfPossessionMetadataBuilder`. |
| `metadata.rs` | `IssuerMetadata` / `CredentialMetadata` type aliases (wrapping `oid4vci` crate types); `convert_metadata` — maps public `IssuerMetadata` to the internal `vc::core::IssuerMetadata` used by `IssuerService`. |
| `credential_offer_resolver.rs` | `CredentialOfferResolver<HC>` — resolves a `credential_offer_uri` link to a `CredentialOfferParams` via HTTP fetch. |
| `credential_issuer_identifier.rs` | `CredentialIssuerIdentifier` enum — parses the issuer identifier from a credential into DID, OID4VCI URL, or Other form; used for `CredentialExtraVerification::CredentialIssuerIdentifier`. |
| `token_validation.rs` | `Introspect<HC>` and `ByJwks<HC>` — two strategies for validating access tokens: OAuth2 introspection endpoint or JWKS signature verification. |
| `protocol_error.rs` | `ProtocolError`, `ErrorType`, `CredentialEndpointError`, `TokenEndpointError`, `CredentialOfferEndpointError` — standard-defined error types mapped from `oid4vci` crate errors. |
| `internal_error.rs` | `InternalError` — non-protocol unexpected errors (parse, vault, KMS, discovery, HTTP, nonce handler, type conversion, etc.). |
| `tests.rs` | Shared test fixtures (`SampleIssuerMetadata`, `SampleCredentialRequest`, sample claims, mock nonce handler; access tokens, the proof JWT, the SD-JWT VC and the JWKS are generated through `test_fixtures`) used across intra-module tests. |

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
- Depends on: `crate::vc::core` (inner `Issuer`, `Holder`, `IssuerService`, `HolderService`, `KeyMetadata`), `crate::vc::pop`, `test_fixtures` (tests only), `crate::vc::claims`, `crate::vc::formats`, `crate::kms`, `crate::vault`, `crate::http`, `crate::nonce`, `crate::did::universal`, `crate::reqwest`, `oid4vci` crate, `oauth2`, `openidconnect`, `ssi`
- Used by: `crate::vc::mod` (re-exports), wrapper targets (Node.js, WASM, UniFFI)

## Constraints
- Nonce spending is scoped to a credential request, not to a key proof: `issue_each` validates every key proof's nonce before it issues anything (`resolve_and_validate_nonce` only checks, never consumes), so a batch doomed by a stale nonce costs no signing operations, while `batch_issuance` collects the nonces it validated and calls `NonceHandler::invalidate` once at the end — including when issuance failed, so a rejected request leaves no reusable nonce behind. A batch may therefore sign every proof over one `c_nonce` or use a fresh one per proof, both of which OID4VCI permits.
- `Nonce` derives `Debug` over its raw secret, so any `#[instrument]` on a function taking or returning a nonce must `skip` it — otherwise the secret lands in TRACE spans, defeating the `ZeroizeOnDrop` treatment the type gets everywhere else.
- The holder is bound to one authorization server at construction, chosen in `auth_server_selection.rs`. `AuthServerHint::from_grants` turns the offer's grants into `PreAuthorized(<named server>)` (a pre-authorized grant wins when both are present) or `AuthorizationCode(<named server>)`; `from_iss_url` (wallet-initiated) passes `AuthorizationCode(None)`. Both grants follow one rule: a server the offer names is used only when the issuer metadata lists it (OID4VCI 1.0 §4.1.1; `listed_offered_server`), since the offer comes over an untrusted channel. Names are compared as exact strings (`IssuerUrl` equality), so `https://as` and `https://as/` differ. Without a usable name: the issuer itself when it lists no server; the only listed server when it lists one; with several, a pre-authorized grant takes the first, and an authorization code grant takes the first whose metadata `supports_authorization_code` (`discover_first_supporting_authorization_code`): grant `authorization_code` **and** an `authorization_endpoint` **and** a `pushed_authorization_request_endpoint`, since the holder only sends PAR. The grant alone is not enough: RFC 8414 defaults an absent `grant_types_supported` to `authorization_code`, so an issuer's own pre-authorized server publishing only `issuer` + `token_endpoint` would pass. A server whose metadata cannot be fetched is skipped; if none qualifies, the first discovered one is kept and the flow fails on it. A holder can be handed a pre-authorized offer after construction (e.g. built with `IssuerDiscovery::Url`, as `demos/oid4vc/holder` does), so `exchange_pre_auth_code_for_token` applies the same rule per request: the grant's named server if listed, else `pre_authorized_server` — the first listed server, kept when the client is bound to another one — else the bound server. A server named but not listed is ignored there too, also when the metadata lists none.
- The authorization code flow sends the offer's `issuer_state` in the pushed authorization request when the `authorization_code` grant carries one (OID4VCI 1.0 §4.1.1 MUST). `get_access_token` threads it into the private `authz_code_flow`; the public `authz_code_flow_with_scope` (wallet-initiated, no offer) passes none.
- Trait objects use `#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]` so the module compiles on both native and WASM targets.
- `HolderBuilder::new` uses an `Arc<HC>` so the same HTTP client can be shared with the internal `UniversalResolver`.
