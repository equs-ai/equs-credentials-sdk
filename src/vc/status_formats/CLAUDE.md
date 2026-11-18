# status_formats — Context

## Purpose
Provides the abstract `API` trait and concrete implementations for token-based VC revocation status lists, currently supporting the JWT Token Status List (draft-ietf-oauth-status-list) format.

## Files

| File | Role |
|------|------|
| mod.rs | `API` trait (create status list, get VC status), `StatusListFormat` enum, shared `Error` type. |
| status_list_token_jwt.rs | `StatusListJwt` — creates compressed bit-string status-list JWTs, fetches and decodes them to return `VCStatus`. Decodes `lst` with or without base64url padding, not through `JsonStatusList::decode`, which requires it. Accepts a plain JWT or this SDK's SD-JWT without disclosures; requires `typ: statuslist+jwt`; verifies the signature and its signer in `verify_status_list_signer` (via `SdJwtAPI::verify_vc_signer`), trusting `x5c` chains only for `get_vc_status_with_trusted_certs`. A token whose key is resolved through a DID (a DID URL `kid`, or a `kid`/`iss` DID) must be signed by the referenced credential's issuer DID, so it is rejected for a credential without one (an `x5c`-issued SD-JWT VC, every mdoc); a token signed by an `x5c` chain is checked against the trusted anchors instead. `get_status_list_entry(uri, idx, issuer, ..)` is the lookup itself, shared by the SD-JWT VC `status` claim and the mdoc MSO `status`; a response typed `application/statuslist+cwt` fails as "status list format not supported". |

## Key types / traits
- `API<CS, ST, SL, MD>` — generic async trait for status list creation and VC status retrieval. `get_vc_status` trusts no X.509 anchors and takes the issuer DID from the credential claims' `iss`; `StatusListJwt::get_vc_status_with_trusted_certs` takes the issuer DID from its caller, plus trusted anchors and the `AnchorPolicy` their chain is checked under (used by `core::VerifierService`, which reads the issuer from the issuer-signed JWT and passes none for an mdoc).
- `StatusListFormat` — `StatusListTokenJwt(SLMetadata)` or `StatusListTokenCwt`.
- `VCStatus` — `Valid | Invalid | Suspended | AppSpecific(u8)`.
- `VCStatuses` — `HashMap<usize, u8>` status index map used when creating a status list.
- `SLMetadata` — metadata for status list JWT creation (URL, size, count).

## Dependencies
- Depends on: `sd_jwt_rs`, `ssi::status::token_status_list`, `base64`, `crate::vc::formats::sd_jwt_vc::SdJwtAPI`, `crate::http::HttpClient`, `test_fixtures` (tests only: status-list tokens generated at runtime)
- Used by: `core::StatusIssuerService`, `formats::sd_jwt_vc` (status check), `mod.rs` (top-level `VCStatus` re-export)
