# core — Context

## Purpose
Defines the abstract SSI actor traits (`Issuer`, `Holder`, `Verifier`, `StatusIssuer`) and their concrete generic service implementations, the prepare/sign split sub-traits (`PrepareCredential`, `SignCredential`) and their shared `UnsignedCredential` wire type, along with all shared metadata and error types.

## Files

| File | Role |
|------|------|
| mod.rs | Module root: re-exports all `api.rs` types, `HolderService`, `IssuerService`, `CredentialSigner`, `VerifierService`, `UnsignedCredential` / `UnsignedSdJwtCredential` / `UnsignedLdpCredential` / `DisclosureStrategy`, default lifetime constants. |
| api.rs | Public API structs and trait definitions: `Issuer`, `Holder`, `Verifier`, `StatusIssuer`, plus the prepare/sign split sub-traits `PrepareCredential`, `SignCredential`. Also `IssuerMetadata`, `CredentialDefinition`, `HolderMetadata`, `PresentationInput`, `PresentationRestriction`, `KeyMetadata`, `Error`, `Result`. |
| issuer.rs | `IssuerService<KH, KMS>` — issues credential offers and mints SD-JWT / JSON-LD VCs via KMS. Implements `PrepareCredential`, `SignCredential`, and `Issuer` (which carries `offer_credential` directly); the `SignCredential` impl delegates to an embedded `CredentialSigner` field. |
| signer.rs | `CredentialSigner<KH, KMS>` — minimal stand-alone `SignCredential` implementation that carries only the KMS and DID resolver (no issuer metadata, no PoP state). The local-signer counterpart to a future external-signer path; embedded by `IssuerService` and used by the wrapper-level `VCCoreCredentialSigner` classes. |
| unsigned.rs | `UnsignedCredential` enum (`SdJwt` / `Ldp`), `UnsignedSdJwtCredential`, `UnsignedLdpCredential`, and `DisclosureStrategy`. Externally-tagged serde shape (`{ "SdJwt": ... }` / `{ "Ldp": ... }`) — the wire format shared by every wrapper's `prepare → sign` split. |
| holder.rs | `HolderService<KH, KMS, V, HC>` — stores/retrieves credentials from Vault, creates VPs, generates PoP. |
| verifier.rs | `VerifierService` — verifies VPs, checks expiry and revocation status across all supported formats. |
| status_issuer.rs | `StatusIssuerService<KH, KMS>` — signs and issues JWT token status-list credentials. |
| tests.rs | Shared test fixtures (`CredTestCase`, mock credential helpers) used across sub-module tests. |

## Key types / traits
- `Issuer` — high-level: `offer_credential`, `issue_credential`. Implemented directly on `IssuerService` (not as a blanket impl over the sub-traits, so coherence is preserved for downstream impls).
- `PrepareCredential` / `SignCredential` — sub-traits for the two-step issuance flow. `prepare_credential` returns an `UnsignedCredential`; `sign_credential` consumes it.
- `Holder` — `accept_credential`, `find_credentials`, `create_presentation`, `create_delegated_credential` (gated `delegate-sd-jwt`).
- `Verifier` — `verify_presentation`.
- `StatusIssuer` — `issue_status_list`.
- `UnsignedCredential` — format-tagged union produced by `PrepareCredential` and consumed by `SignCredential`; externally-tagged JSON serialization is the cross-wrapper wire contract.
- `PresentationInput` / `PresentationRestriction` — describe what the verifier requires.
- `PresentationRestrictionValue` — `Const | Pattern | ArrayOfValues` filter modes.

## Dependencies
- Depends on: `crate::vc::formats`, `crate::vc::pop`, `crate::vc::status_formats`, `crate::kms`, `crate::vault`, `crate::http`, `ssi::JsonPointerBuf` (LDP mandatory-claims paths)
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vault` (Vault trait interactions), all three wrappers (`nodejs`, `uniffi`, `wasm`) for the `VCCoreCredentialSigner` surface
