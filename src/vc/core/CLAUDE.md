# core — Context

## Purpose
Defines the abstract SSI actor traits (`Issuer`, `Holder`, `Verifier`, `StatusIssuer`) and their concrete generic service implementations, along with all shared metadata and error types.

## Files

| File | Role |
|------|------|
| mod.rs | Module root: re-exports all `api.rs` types, `HolderService`, `IssuerService`, `VerifierService`, default lifetime constants. |
| api.rs | Public API structs and trait definitions: `Issuer`, `Holder`, `Verifier`, `StatusIssuer`, `IssuerMetadata`, `CredentialDefinition`, `HolderMetadata`, `PresentationInput`, `PresentationRestriction`, `KeyMetadata`, `Error`, `Result`. |
| issuer.rs | `IssuerService<KH, KMS>` — issues credential offers and mints SD-JWT / JSON-LD VCs via KMS. |
| holder.rs | `HolderService<KH, KMS, V, HC>` — stores/retrieves credentials from Vault, creates VPs, generates PoP. |
| verifier.rs | `VerifierService` — verifies VPs, checks expiry and revocation status across all supported formats. |
| status_issuer.rs | `StatusIssuerService<KH, KMS>` — signs and issues JWT token status-list credentials. |
| tests.rs | Shared test fixtures (`CredTestCase`, mock credential helpers) used across sub-module tests. |

## Key types / traits
- `Issuer` — `offer_credential`, `issue_credential`.
- `Holder` — `accept_credential`, `find_credentials`, `create_presentation`.
- `Verifier` — `verify_presentation`.
- `StatusIssuer` — `issue_status_list`.
- `PresentationInput` / `PresentationRestriction` — describe what the verifier requires.
- `PresentationRestrictionValue` — `Const | Pattern | ArrayOfValues` filter modes.

## Dependencies
- Depends on: `crate::vc::formats`, `crate::vc::pop`, `crate::vc::status_formats`, `crate::kms`, `crate::vault`, `crate::http`
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vault` (Vault trait interactions)
