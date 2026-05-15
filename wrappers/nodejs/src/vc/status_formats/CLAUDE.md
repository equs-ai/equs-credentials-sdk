# vc/status_formats — Context

## Purpose
Provides NAPI-RS bindings for credential status list format types used in the VC status subsystem. Bridges the core `StatusListFormat` enum and token status list `VCStatus` variants into NAPI-compatible types consumed by `vc/core` for status issuance and verification.

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines `JsStatusListFormat` (object with `format: JsStatusListFormatFmt` and `payload`), `JsStatusListFormatFmt` enum (`StatusListTokenJwt`, `StatusListTokenCwt`), and `TslVcStatusType` string enum (`VALID`, `INVALID`, `SUSPENDED`, `APPSPECIFIC`). Provides `TryFrom` conversions between Rust and NAPI representations. |

## Key types / traits
- `JsStatusListFormat` — NAPI object wrapping `StatusListFormat`; carries format discriminant and payload JSON object.
- `TslVcStatusType` — NAPI string enum mapping to `status_list_token_jwt::VCStatus` variants.

## Dependencies
- Depends on: `agent_sdk::vc::status_formats` (`StatusListFormat`, `status_list_token_jwt::VCStatus`), `agent_sdk::vc::TslVcStatus`
- Used by: `crate::vc::core` (for `JsStatusListDefinition`, `JsVCStatus`)
