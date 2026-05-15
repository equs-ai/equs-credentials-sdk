# oid4vc/shared/src — Context

## Purpose
Shared library used by the `holder`, `issuer`, and `verifier` demo binaries. Provides common request/response types for OID4VP authorization and a helper for building verifiable presentations.

## Files

| File | Role |
|------|------|
| `lib.rs` | `AuthRequestQuery` — query params for authorization requests; `PresentationQueryType` enum (`DCQL` / `PresentationExchange`); default helpers |
| `vp.rs` | VP construction helpers shared across holder and verifier roles |

## Key types / traits
- `AuthRequestQuery { response_type, response_mode, query_type }` — deserialised from HTTP query string by actix handlers.
- `PresentationQueryType` — `DCQL | PresentationExchange` (default: `DCQL`).

## Dependencies
- Depends on: `agent_sdk::vc::oid4vp::{ResponseMode, ResponseType}`, `serde`, `strum_macros`
- Used by: `demos/oid4vc/holder`, `demos/oid4vc/verifier`

## Constraints
- Demo / development use only.
