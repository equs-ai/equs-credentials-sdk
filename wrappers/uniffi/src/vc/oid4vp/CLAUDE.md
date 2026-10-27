# vc/oid4vp — Context

## Purpose
Exposes the OID4VP (OpenID for Verifiable Presentations) protocol layer to Kotlin and Swift via UniFFI. Provides the `OID4VPHolder` UniFFI object for the full credential presentation flow, along with supporting types for authorization requests, authorization responses, presentation results, and transaction data. For dSD-JWT delegation it covers the delegating Holder (the user's wallet, which answers a `delegate` item with a grant), not the Delegate Holder (the Agent that stores and re-presents the grant) or the Verifier.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared OID4VP types: `AuthorizationResponse` enum (Plain/Jwe), `AuthorizationResponseObject` record, `PresentationResult` enum (AuthResponse/RedirectUri/Presented), `AuthorizationRequest` record, `IdTokenMetadata`, `AuthorizationResponseMetadata` and `DeclineReason` remote records, the `DeclineAuthorizationRequestError` remote enum, and the SDK's transaction-data types as remote types: `TransactionDataItem` record, `TransactionDataItemTypeContent` and `DelegateSdJwtTransactionDataFormat` and `HashAlgorithm` enums, `DelegateSdJwtTransactionData` record. Provides `TryFrom` conversions between the hand-written UniFFI types and core SDK types; transaction-data items pass through unconverted. `check_delegate_items` checks a parsed request that is about to be answered with a presentation: no `delegate` item unless the holder allows delegation, and every `delegate` item parsed as one. |
| `holder.rs` | `OID4VPHolder` — UniFFI object (async_runtime = tokio) wrapping any `equs_sdk::vc::oid4vp::Holder` impl. Exposes `get_authorization_request`, `present_credentials_auto`, `find_vcs_for_presentation`, `present_credentials`, `decline_authorization_request`, and `get_credential_status`. `decline_authorization_request` takes an optional `reason: DeclineReason`, declared `#[uniffi::method(default(reason = None))]` so Kotlin and Swift callers may omit it. The crate builds the SDK with `delegate-sd-jwt`; a holder built with `allow_delegation = true` answers a `delegate` item in `present_credentials(_auto)` with a dSD-JWT grant for each credential it targets, any other holder rejects such a request on present / find (declining still works). |
| `builder.rs` | Builder function for constructing `OID4VPHolder` with KMS, vault, HTTP client, optional wallet metadata, PoP, DID resolver, and nonce handler. Its constructor's last argument, `allow_delegation: Option<bool>` (omitted / `None` means off), opts the holder into answering `delegate` items with a grant; an app enables it only once it shows the user what is delegated and to whom. |

## Key types / traits
- `OID4VPHolder` — UniFFI async object for the full OID4VP presentation flow.
- `AuthorizationRequest` — UniFFI record representing a resolved OID4VP authorization request (client ID, presentation definition, nonce, response metadata).
- `PresentationResult` — UniFFI enum for the three possible presentation outcomes.
- `AuthorizationResponse` — UniFFI enum for plain or JWE-encrypted responses.
- `TransactionDataItem` — the SDK's item as a remote record: `credentialIds`, `transactionDataHashesAlg` (`HashAlgorithm` enum) and `content`, a `TransactionDataItemTypeContent`: `DelegateSdJwt(DelegateSdJwtTransactionData)` for a `delegate` item (`format`, `delegatePayloadDisclosure`, `delegateDisclosures`), `Unknown { type, data }` for every other type, `data` being a `JsonMap`. Upstream parses a `delegate` item without its delegate fields, or with an unrecognized `format`, as `Unknown` with type `delegate`. In `present_credentials(_auto)` and `find_vcs_for_presentation`, `check_delegate_items` rejects every item of type `delegate`, parsed or not, unless the holder allows delegation, and with delegation allowed still rejects one that did not parse, since the SDK would answer it with an ordinary presentation — the error names the missing or unsupported field (`format`, `delegate_payload_disclosure`) without quoting its value; `decline_authorization_request` accepts both.

## Dependencies
- Depends on: `equs_sdk::vc::oid4vp`, `crate::common`, `crate::crypto::KeyMetadata`, `crate::vault` (for `CredentialEntry`, `CredentialsFindResult`), `crate::vc`, `crate::utils`
- Used by: Kotlin/Swift OID4VP holder integrations
