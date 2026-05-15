# status_formats — Context

## Purpose
Provides the abstract `API` trait and concrete implementations for token-based VC revocation status lists, currently supporting the JWT Token Status List (draft-ietf-oauth-status-list) format.

## Files

| File | Role |
|------|------|
| mod.rs | `API` trait (create status list, get VC status), `StatusListFormat` enum, shared `Error` type. |
| status_list_token_jwt.rs | `StatusListJwt` — creates compressed bit-string status-list JWTs, fetches and decodes them to return `VCStatus`. |

## Key types / traits
- `API<CS, ST, SL, MD>` — generic async trait for status list creation and VC status retrieval.
- `StatusListFormat` — `StatusListTokenJwt(SLMetadata)` or `StatusListTokenCwt`.
- `VCStatus` — `Valid | Invalid | Suspended | AppSpecific(u8)`.
- `VCStatuses` — `HashMap<usize, u8>` status index map used when creating a status list.
- `SLMetadata` — metadata for status list JWT creation (URL, size, count).

## Dependencies
- Depends on: `sd_jwt_rs`, `ssi_status::token_status_list`, `crate::vc::formats::sd_jwt_vc::SdJwtAPI`, `crate::http::HttpClient`
- Used by: `core::StatusIssuerService`, `formats::sd_jwt_vc` (status check), `mod.rs` (top-level `VCStatus` re-export)
