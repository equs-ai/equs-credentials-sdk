# core — Context

## Purpose
Defines the abstract protocol actor traits (`Issuer`, `Holder`, `Verifier`, `StatusIssuer`) and their concrete generic service implementations, the prepare/sign split sub-traits (`PrepareCredential`, `SignCredential`) and their shared `UnsignedCredential` wire type, along with all shared metadata and error types.

## Files

| File | Role |
|------|------|
| mod.rs | Module root: re-exports all `api.rs` types, `HolderService`, `IssuerService`, `CredentialSigner`, `VerifierService`, `UnsignedCredential` / `UnsignedSdJwtCredential` / `UnsignedLdpCredential` / `DisclosureStrategy`, default lifetime constants. |
| api.rs | Public API structs and trait definitions: `Issuer`, `Holder`, `Verifier`, `StatusIssuer`, plus the prepare/sign split sub-traits `PrepareCredential`, `SignCredential`. Also `IssuerMetadata`, `CredentialDefinition`, `HolderMetadata`, `PresentationInput`, `PresentationRestriction`, `KeyMetadata`, `Error`, `Result`. |
| issuer.rs | `IssuerService<KH, KMS>` — issues credential offers and mints SD-JWT / JSON-LD VCs via KMS. Implements `PrepareCredential`, `SignCredential`, and `Issuer` (which carries `offer_credential` directly); the `SignCredential` impl delegates to an embedded `CredentialSigner` field. |
| signer.rs | `CredentialSigner<KH, KMS>` — minimal stand-alone `SignCredential` implementation that carries only the KMS and DID resolver (no issuer metadata, no PoP state). The local-signer counterpart to a future external-signer path; embedded by `IssuerService` and used by the wrapper-level `VCCoreCredentialSigner` classes. |
| unsigned.rs | `UnsignedCredential` enum (`SdJwt` / `Ldp`), `UnsignedSdJwtCredential`, `UnsignedLdpCredential`, and `DisclosureStrategy`. Externally-tagged serde shape (`{ "SdJwt": ... }` / `{ "Ldp": ... }`) — the wire format shared by every wrapper's `prepare → sign` split. |
| holder.rs | `HolderService<KH, KMS, V, HC>` — stores/retrieves credentials from Vault, creates VPs, generates PoP. |
| verifier.rs | `VerifierService` — verifies VPs, checks expiry and revocation status across all supported formats. Status list tokens are verified against the same `VerificationParams.trusted_certs` as credentials. `verify_presentation` checks the issuer chain for integrity only (`AnchorPolicy::IntegrityOnly`), then evaluates it against `VerificationParams.issuer_trust` anchors (`vc::trust::issuer`; unset, `trusted_certs` are the anchors under `Enforce`), and returns the outcome alongside the claims. Under `Enforce` an issuer the outcome rejects fails with `Error::IssuerNotTrusted`, which carries the whole verification so a caller verifying several credentials (OID4VP) can report all of them. JSON-LD presentations, and every presentation on wasm, are verified against `trusted_certs` and are `not_evaluated` or, for a PID, QEAA or PuB-EAA, `did_issuer_not_allowed`. The status-list chain is checked under the anchors in `Enforce` mode and for a trusted issuer in `Report` mode (`status_anchor_policy`), since integrity-only would let any certificate chain sign a trusted issuer's status list; for an issuer `Report` returns untrusted it is checked for integrity only, plus revocation where it reaches an anchor. A revoked or expired path from the issuer chain to an anchor fails the verification in either mode. An mdoc's MSO `status.status_list` is checked the same way in every entry point (`obtain_credential_status` reads it unverified); an MSO `status` without `status_list` (e.g. `identifier_list` only) fails with "status mechanism not supported", and an `identifier_list` beside a `status_list` is not fetched. |
| status_issuer.rs | `StatusIssuerService<KH, KMS>` — signs and issues JWT token status-list credentials. |
| tests.rs | Shared test fixtures (`CredTestCase`, mock credential helpers) used across sub-module tests. |

## Key types / traits
- `Issuer` — high-level: `offer_credential`, `issue_credential`. Implemented directly on `IssuerService` (not as a blanket impl over the sub-traits, so coherence is preserved for downstream impls).
- `PrepareCredential` / `SignCredential` — sub-traits for the two-step issuance flow. `prepare_credential` returns an `UnsignedCredential`; `sign_credential` consumes it.
- `Holder` — `accept_credential`, `find_credentials`, `create_presentation`, `create_delegated_credential` (gated `delegate-sd-jwt`).
- `Verifier` — `verify_presentation`, `obtain_credential_status`, and (gated `delegate-sd-jwt`) `verify_delegation`: verifies a dSD-JWT grant like a presentation but tolerates un-narrowed Delegate Payload alternatives, and returns two halves — `issued_vc` (issuer-signed claims) and `delegations` (per-hop alternatives), keyed by `crate::vc::claims::{ISSUED_VC_CLAIM, DELEGATIONS_CLAIM}`. Its `Option<HolderBinder>` reaches `sd_jwt_rs`, which binds every alternative of the final hop. It returns an `IssuerTrustVerification`: the issued credential has a DID issuer, so its outcome is `IssuerTrustOutcome::without_chain` of the category of `issued_vc` (classifying the outer claims would always give EAA), enforced like `verify_presentation`. Defaulted on the trait so implementors and wrappers are unaffected; `VerifierService` overrides it and shares `check_sd_jwt_expiry_and_status` with `verify_presentation`.
- `StatusIssuer` — `issue_status_list`.
- `UnsignedCredential` — format-tagged union produced by `PrepareCredential` and consumed by `SignCredential`; externally-tagged JSON serialization is the cross-wrapper wire contract.
- `PresentationInput` / `PresentationRestriction` — describe what the verifier requires.
- `PresentationRestrictionValue` — `Const | Pattern | ArrayOfValues` filter modes.

## Dependencies
- Depends on: `crate::vc::formats`, `crate::vc::pop`, `crate::vc::status_formats`, `crate::kms`, `crate::vault`, `crate::http`, `ssi::JsonPointerBuf` (LDP mandatory-claims paths)
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vault` (Vault trait interactions), all three wrappers (`nodejs`, `uniffi`, `wasm`) for the `VCCoreCredentialSigner` surface
