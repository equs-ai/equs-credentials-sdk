# metadata — Context

## Purpose
Resolves `CredentialMetadata` (type string, format, key-id, claim-field paths) from a held `Credential`, verifying DID ownership before returning.

## Files

| File | Role |
|------|------|
| mod.rs | `CredentialMetadataProcessor` trait and `DefaultMetadataProcessor` implementation for SD-JWT and JSON-LD VC formats. |

## Key types / traits
- `CredentialMetadataProcessor` — trait with `resolve_metadata(credential, key_metadata) -> Result<CredentialMetadata>`.
- `DefaultMetadataProcessor` — default implementation; extracts `vct` (SD-JWT) or last `type` (JSON-LD) and validates DID match: the `sub` (SD-JWT) or `credentialSubject.id` (JSON-LD) must equal the key metadata's DID (its `did_url` before `#`) or the whole `did_url`.
- `Error` — `FormatNotSupported`, `Resolving`.

## Dependencies
- Depends on: `crate::vc::formats::HasClaims`, `crate::vc::core::KeyMetadata`, `crate::vc::claims::Claim`, `crate::utils::json`, `test_fixtures` (tests only: EdDSA SD-JWT fixtures under module-local Ed25519 keys)
- Used by: the Aries issuance holder (before storing a received credential), the wrappers' `resolve_metadata`, `InMemVault` test helpers
