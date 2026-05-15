# metadata — Context

## Purpose
Resolves `CredentialMetadata` (type string, format, key-id, claim-field paths) from a held `Credential`, verifying DID ownership before returning.

## Files

| File | Role |
|------|------|
| mod.rs | `CredentialMetadataProcessor` trait and `DefaultMetadataProcessor` implementation for SD-JWT and JSON-LD VC formats. |

## Key types / traits
- `CredentialMetadataProcessor` — trait with `resolve_metadata(credential, key_metadata) -> Result<CredentialMetadata>`.
- `DefaultMetadataProcessor` — default implementation; extracts `vct` (SD-JWT) or last `type` (JSON-LD) and validates DID match.
- `Error` — `FormatNotSupported`, `Resolving`.

## Dependencies
- Depends on: `crate::vc::formats::HasClaims`, `crate::vc::core::KeyMetadata`, `crate::vc::claims::Claim`, `crate::utils::json`
- Used by: `core::HolderService` (after credential acceptance)
