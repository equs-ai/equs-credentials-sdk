# vc/core — Context

## Purpose
Provides NAPI-RS bindings for the protocol-agnostic VC core layer, including `VCCoreIssuer`, `VCCoreHolder`, `VCCoreVerifier`, `VCCoreStatusIssuer`, and the stand-alone `_VCCoreCredentialSigner` (exposed publicly via the hand-written `VCCoreCredentialSigner` TS wrapper). Also defines all shared data types used across the VC subsystem: credential formats, presentation types, key metadata, proof-of-possession metadata, credential definitions, status information, and status list structures.

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines all shared NAPI types: `JsCredential`, `JsCredentialMetadata`, `JsVCFormat`, `JsAlg`, `JsProof`, `JsCredentialRequest`, `JsCredentialOffer`, `JsCredentialDefinition`, `JsIssuerMetadata`, `JsHolderMetadata`, `JsPresentation`, `JsPresentationInput`, `JsPresentationRestriction`, `JsProofOfPossessionMetadata`, `JsHolderBinder`, `JsCredentialStatusInfo`, `JsVCStatusesData`, `JsStatusList`, `JsVCStatus`, `JsStatusListDefinition`, `JsStatusIssuerMetadata`, and many supporting enums. |
| `issuer.rs` | `VCCoreIssuer` — NAPI class wrapping `Box<dyn IssuerWithPrepare>` (a private extension trait that combines `Issuer + PrepareCredential`). Exposes `offerCredential`, `issueCredential`, and `prepareCredential`. `prepareCredential` returns the externally-tagged `UnsignedCredential` JSON shape consumable by `VCCoreCredentialSigner.signCredential`. Factory function `create_issuer` builds an `IssuerService`. |
| `signer.rs` | `JsVCCoreCredentialSigner` — raw NAPI class (`js_name = "_VCCoreCredentialSigner"`) wrapping `Box<dyn SignCredential>` over a `CredentialSigner`. Exposes `signCredential(unsigned)` taking the externally-tagged `UnsignedCredential` JSON. The friendly `VCCoreCredentialSigner` TS class in `types/vc/core/signer.ts` wraps this with `contextEnsuredKms` so JS callbacks preserve `this`. |
| `holder.rs` | `VCCoreHolder` — NAPI class wrapping `Box<dyn Holder>`. Exposes `requestCredential`, `storeCredential`, `verifyCredential`, `createPresentationAuto`, `findVcsForPresentation`, `createPresentation`, and `getCredentialStatus`. Factory function `create_holder` builds a `HolderService`. |
| `verifier.rs` | `VCCoreVerifier` — NAPI class wrapping `Box<dyn Verifier>`. Exposes `verifyPresentation` and `obtainCredentialStatus`. Factory function `create_verifier` builds a `VerifierService`. |
| `status_issuer.rs` | `VCCoreStatusIssuer` — NAPI class wrapping `Box<dyn StatusIssuer>`. Exposes `issueStatusList`. Factory function `create_status_issuer` builds a `StatusIssuerService`. |
| `error.rs` | Maps `CoreError` variants to `EncodableError` using the `JsError` string enum. |

## Key types / traits
- `VCCoreIssuer` — Protocol-agnostic issuer API; supports both one-shot `issueCredential` and the two-step `prepareCredential` → `VCCoreCredentialSigner.signCredential` split via the `IssuerWithPrepare` extension trait.
- `VCCoreCredentialSigner` (TS wrapper in `types/vc/core/signer.ts`) / `_VCCoreCredentialSigner` (raw napi class) — Stand-alone signer for the prepare/sign split; carries only a KMS and DID resolver, useful when signing is driven from application code (HSM-backed adapters, remote signing services).
- `VCCoreHolder` — Protocol-agnostic holder API with vault integration.
- `VCCoreVerifier` — Protocol-agnostic verifier API.
- `VCCoreStatusIssuer` — Status list issuer API.
- `JsCredential`, `JsPresentation` — Core VC payload types.
- `JsIssuerMetadata`, `JsHolderMetadata` — Service configuration types.
- `UnsignedCredential` (TS type, shared from `wrappers/types/vc/unsigned-credential.ts`) — externally-tagged wire shape exchanged between `prepareCredential` and `signCredential`.

## Dependencies
- Depends on: `agent_sdk::vc::core` (including `CredentialSigner`, `UnsignedCredential`, and the `PrepareCredential` / `SignCredential` traits), `agent_sdk::vc` (credential/presentation types), `agent_sdk::nonce`, `crate::kms::JsKms`, `crate::vault::JsVault`, `crate::did::JsUniversalDIDResolver`, `crate::http::ReqwestHttpClient`, `crate::vc::status_formats`, `crate::utils::{from_json_object, to_json_object}`
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vc::mod`, `crate::inmem::vault`
