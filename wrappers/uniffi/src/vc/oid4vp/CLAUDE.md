# vc/oid4vp — Context

## Purpose
Exposes the OID4VP (OpenID for Verifiable Presentations) protocol layer to Kotlin and Swift via UniFFI. Provides the `OID4VPHolder` UniFFI object for the full credential presentation flow, along with supporting types for authorization requests, authorization responses, presentation results, and transaction data.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared OID4VP types: `AuthorizationResponse` enum (Plain/Jwe), `AuthorizationResponseObject` record, `PresentationResult` enum (AuthResponse/RedirectUri/Presented), `AuthorizationRequest` record, `TransactionDataItem` record, `IdTokenMetadata` and `AuthorizationResponseMetadata` remote records. Provides `TryFrom` conversions between UniFFI types and core SDK types; `TransactionDataItem` converts both ways through the SDK item's own serde, so no field is lost and field order is kept. `presentable_request` converts a request that is about to be answered with a presentation. |
| `holder.rs` | `OID4VPHolder` — UniFFI object (async_runtime = tokio) wrapping any `equs_sdk::vc::oid4vp::Holder` impl. Exposes `get_authorization_request`, `present_credentials_auto`, `find_vcs_for_presentation`, `present_credentials`, `decline_authorization_request`, and `get_credential_status`. The crate builds the SDK with `delegate-sd-jwt`, so `present_credentials(_auto)` answer a `delegate` item with a dSD-JWT grant for each credential it targets. |
| `builder.rs` | Builder function for constructing `OID4VPHolder` with KMS, vault, HTTP client, optional wallet metadata, PoP, DID resolver, and nonce handler. |

## Key types / traits
- `OID4VPHolder` — UniFFI async object for the full OID4VP presentation flow.
- `AuthorizationRequest` — UniFFI record representing a resolved OID4VP authorization request (client ID, presentation definition, nonce, response metadata).
- `PresentationResult` — UniFFI enum for the three possible presentation outcomes.
- `AuthorizationResponse` — UniFFI enum for plain or JWE-encrypted responses.
- `TransactionDataItem` — `type`, `credentialIds`, `transactionDataHashesAlg`, plus `data` (default `null`): every other field of the item as a JSON object, in the item's own key order, `null` when there is none — e.g. a `delegate` item's `format` and `delegate_payload_disclosure`. The SDK hashes the re-serialized item, so the key order is part of the hash and callers pass `data` back unchanged. Record → SDK fails with `Error::OID4VPHolder` when `data` is not an object, repeats `type` / `credential_ids` / `transaction_data_hashes_alg`, or the assembled item does not parse (an unknown hash algorithm); the message never quotes the item. `presentable_request` additionally rejects, for `present_credentials(_auto)` and `find_vcs_for_presentation`, a `delegate` item that did not parse as one — no delegate fields or an unrecognized `format`, which upstream parses as an unknown type; `decline_authorization_request` still accepts it.

## Dependencies
- Depends on: `equs_sdk::vc::oid4vp`, `crate::common`, `crate::crypto::KeyMetadata`, `crate::vault` (for `CredentialEntry`, `CredentialsFindResult`), `crate::vc`, `crate::utils`
- Used by: Kotlin/Swift OID4VP holder integrations
