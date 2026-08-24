# vc/core — Context

## Purpose
Exposes the protocol-agnostic VC core API (`Issuer`, `Holder`, `Verifier`, `StatusIssuer`) and all shared payload types to Kotlin and Swift via UniFFI. Mirrors `wrappers/nodejs/src/vc/core/`.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; declares `pub mod signer` and re-exports all submodules. |
| `signer.rs` | `VCCoreCredentialSigner` UniFFI object wrapping `Box<dyn SignCredential>`. Constructed from a foreign-trait `Kms` + `UniversalDIDResolver`. Exposes `sign_credential(unsigned_credential: JsonValue)` — deserializes the externally-tagged `UnsignedCredential` JSON string and delegates to a `CredentialSigner<WrappedKeyHandle, WrappedKms>`. |
| `types.rs` | Shared payload types. Most are exposed via `#[uniffi::remote(...)]` on the SDK structs (`Proof`, `Display`, `IssuerMetadataData`, `CredentialOfferData`, `CredentialRequest`, `CredentialRequestData`, `CredentialDefinitionData`, `CredentialStatusInfo`, `HolderBinder`, `HolderMetadata`, `PopFormat`, `PresentationInput`, `PresentationRestriction`, `PresentationRestrictionValue`, `StatusList`). The few remaining hand-written wrapper records (`CredentialDefinition`, `IssuerMetadata`, `CredentialOffer`, `CredentialOfferContent`, `VCStatusesData`, `StatusListDefinition`, `StatusIssuerMetadata`, `SupportedProofEntry`, `StatusEntry`) exist because the SDK uses non-`String` HashMap keys (`pop::Format`, `usize`) which UniFFI cannot bridge directly — typed `Vec<Entry>` projections are used at the FFI boundary. |
| `status_formats.rs` | `SLMetadata` record + `StatusListFormat` wrapper enum bridging `equs_sdk::vc::status_formats::StatusListFormat`. |
| `issuer.rs` | `VCCoreIssuer` UniFFI object with `#[uniffi::constructor]` `new(kms, metadata, did_resolver)`. Exposes `offerCredential`, `issueCredential`, and `prepareCredential`. Uses a private `IssuerWithPrepare` combining trait (`Issuer + PrepareCredential`) so `prepareCredential` is accessible on the boxed service. |
| `holder.rs` | `VCCoreHolder` UniFFI object with `#[uniffi::constructor]` `new(kms, vault, metadata, did_resolver, http_client)`. |
| `verifier.rs` | `VCCoreVerifier` UniFFI object with `#[uniffi::constructor]` `new(verifier_id, did_resolver)`. |
| `status_issuer.rs` | `VCCoreStatusIssuer` UniFFI object with `#[uniffi::constructor]` `new(kms, metadata)`; also re-exports the convenience `OID4VCIStatusIssuerBuilder`. |

## Key types / traits
- `VCCoreIssuer` — Protocol-agnostic issuer; supports one-shot `issueCredential` and the two-step `prepareCredential` → `VCCoreCredentialSigner.signCredential` split. `prepareCredential` returns the externally-tagged `UnsignedCredential` as a `JsonValue` (JSON string at the FFI boundary).
- `VCCoreHolder`, `VCCoreVerifier`, `VCCoreStatusIssuer` — UniFFI objects wrapping `Box<dyn Trait>` from `equs_sdk::vc::core`.
- Payload types use typed UniFFI Records/Enums end-to-end; `claims` parameters carry an opaque user-supplied JSON map as `JsonValue`.
- `SupportedProofEntry { format: PopFormat, algs: Vec<Alg> }` and `StatusEntry { index: u32, status: u8 }` are FFI-boundary projections of SDK HashMaps whose keys aren't UniFFI-typeable (`pop::Format` enum key, `usize` key).

## Dependencies
- Depends on: `equs_sdk::vc::core`, `equs_sdk::vc::status_formats`, `crate::common`, `crate::http`, `crate::kms`, `crate::vault`, `crate::did`
- Used by: Kotlin/Swift integration tests and downstream consumer apps.
