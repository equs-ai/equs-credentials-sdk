# oid4vc/issuer/src — Context

## Purpose
Runnable demo binary implementing the Issuer role in a full OID4VCI flow. Exposes actix-web endpoints for credential metadata discovery, token exchange (pre-authorized-code and authorization-code grants), and credential issuance.

## Files

| File | Role |
|------|------|
| `main.rs` | Entry point: wires `LocalKms`, actix `AppState` with `Issuer`; registers handlers for `/.well-known/openid-credential-issuer`, `/token`, `/credential`, and `/credential-offer`; issues SD-JWT credentials |

## Key types / traits
- Uses `vc::oid4vci::Issuer` from `agent_sdk`.
- Exposes `IssuerMetadata`, `AuthorizationMetadata`, `CredentialOfferGrants`, `PreAuthorizedCodeGrant`, `AuthorizationCodeGrant`.
- `AppState` — actix shared state holding the `Issuer` instance and a pre-generated `did:key` DID.

## Dependencies
- Depends on: `agent_sdk` (oid4vci, kms, inmem, vc::core), `actix-web`, `tokio`
- Used by: developers demonstrating the issuer role end-to-end

## Constraints
- Demo / development use only; hard-codes credential definitions and uses in-memory storage.
