# oid4vc/shared/src — Context

## Purpose
Shared library used by the `holder`, `issuer`, and `verifier` demo binaries. Provides common request/response types for OID4VP authorization and a helper for building verifiable presentations.

## Files

| File | Role |
|------|------|
| `lib.rs` | `AuthRequestQuery` — query params for authorization requests; `PresentationQueryType` enum (`DCQL` / `PresentationExchange`); default helpers |
| `vp.rs` | VP construction helpers shared across holder and verifier roles |
| `voucher.rs` | dSD-JWT voucher demo: `VOUCHER_VCT`, `VOUCHER_DCQL_ID`, `generate_purchase_id`, the Merchant's `voucher_dcql` (`purchase_id` only in the preferred claim set, since the Verifier checks DCQL claims against issuer-signed claims), `purchase_id_from_dcql` for the Agent, and `delegated_purchase_id`, which reads `purchase_id` from the last hop under the verified `delegations` |

## Key types / traits
- `AuthRequestQuery { response_type, response_mode, query_type }` — deserialized from HTTP query string by actix handlers.
- `PresentationQueryType` — `DCQL | PresentationExchange` (default: `DCQL`).

## Dependencies
- Depends on: `equs_sdk::vc::oid4vp::{ResponseMode, ResponseType}`, `serde`, `strum_macros`
- Used by: `demos/oid4vc/holder`, `demos/oid4vc/verifier`, `demos/oid4vc/agent`

## Constraints
- Demo / development use only.
