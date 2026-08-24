# vc/oid4vp — Context

## Purpose
Exposes the OID4VP (OpenID for Verifiable Presentations) protocol layer to Kotlin and Swift via UniFFI. Provides the `OID4VPHolder` UniFFI object for the full credential presentation flow, along with supporting types for authorization requests, authorization responses, presentation results, and transaction data.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared OID4VP types: `AuthorizationResponse` enum (Plain/Jwe), `AuthorizationResponseObject` record, `PresentationResult` enum (AuthResponse/RedirectUri/Presented), `AuthorizationRequest` record, `TransactionDataItem` record, `IdTokenMetadata` and `AuthorizationResponseMetadata` remote records. Provides `TryFrom` conversions between UniFFI types and core SDK types. |
| `holder.rs` | `OID4VPHolder` — UniFFI object (async_runtime = tokio) wrapping any `equs_sdk::vc::oid4vp::Holder` impl. Exposes `get_authorization_request`, `present_credentials_auto`, `find_vcs_for_presentation`, `present_credentials`, `decline_authorization_request`, and `get_credential_status`. |
| `builder.rs` | Builder function for constructing `OID4VPHolder` with KMS, vault, HTTP client, optional wallet metadata, PoP, DID resolver, and nonce handler. |

## Key types / traits
- `OID4VPHolder` — UniFFI async object for the full OID4VP presentation flow.
- `AuthorizationRequest` — UniFFI record representing a resolved OID4VP authorization request (client ID, presentation definition, nonce, response metadata).
- `PresentationResult` — UniFFI enum for the three possible presentation outcomes.
- `AuthorizationResponse` — UniFFI enum for plain or JWE-encrypted responses.

## Dependencies
- Depends on: `equs_sdk::vc::oid4vp`, `crate::common`, `crate::crypto::KeyMetadata`, `crate::vault` (for `CredentialEntry`, `CredentialsFindResult`), `crate::vc`, `crate::utils`
- Used by: Kotlin/Swift OID4VP holder integrations
