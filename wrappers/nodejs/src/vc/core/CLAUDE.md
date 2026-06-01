# vc/core — Context

## Purpose
Provides NAPI-RS bindings for the protocol-agnostic VC core layer. All four service classes (`VCCoreIssuer`, `VCCoreHolder`, `VCCoreVerifier`, `VCCoreStatusIssuer`) use the underscore-prefixed `js_name` convention so that TypeScript wrappers in `types/vc/core/` can expose them under the clean names with `contextEnsuredKms`/`contextEnsuredVault` applied internally. Also defines all shared data types used across the VC subsystem.

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines all shared NAPI types: `JsCredential`, `JsCredentialMetadata`, `JsVCFormat`, `JsAlg`, `JsProof`, `JsCredentialRequest`, `JsCredentialOffer`, `JsCredentialDefinition`, `JsIssuerMetadata`, `JsHolderMetadata`, `JsPresentation`, `JsPresentationInput`, `JsPresentationRestriction`, `JsProofOfPossessionMetadata`, `JsHolderBinder`, `JsCredentialStatusInfo`, `JsVCStatusesData`, `JsStatusList`, `JsVCStatus`, `JsStatusListDefinition`, `JsStatusIssuerMetadata`, and many supporting enums. |
| `issuer.rs` | `VCCoreIssuer` — raw NAPI class (`js_name = "_VcCoreIssuer"`) wrapping `Box<dyn IssuerWithPrepare>`. The public `VcCoreIssuer` TS wrapper in `types/vc/core/issuer.ts` applies `contextEnsuredKms` and unwraps `didResolver.inner`. Exposes `offerCredential`, `issueCredential`, `prepareCredential`. Also ships a deprecated `create_issuer` factory. |
| `signer.rs` | `JsVCCoreCredentialSigner` — raw NAPI class (`js_name = "_VCCoreCredentialSigner"`) wrapping `Box<dyn SignCredential>` over a `CredentialSigner`. Exposes `signCredential(unsigned)` taking the externally-tagged `UnsignedCredential` JSON. The friendly `VCCoreCredentialSigner` TS class in `types/vc/core/signer.ts` wraps this with `contextEnsuredKms` so JS callbacks preserve `this`. |
| `holder.rs` | `VCCoreHolder` — raw NAPI class (`js_name = "_VcCoreHolder"`) wrapping `Box<dyn Holder>`. The public `VcCoreHolder` TS wrapper in `types/vc/core/holder.ts` applies `contextEnsuredKms`, `contextEnsuredVault`, and unwraps `didResolver.inner`. Exposes `requestCredential`, `storeCredential`, `verifyCredential`, `createPresentationAuto`, `findVcsForPresentation`, `createPresentation`, `getCredentialStatus`. Also ships a deprecated `create_holder` factory. |
| `verifier.rs` | `VCCoreVerifier` — raw NAPI class (`js_name = "_VcCoreVerifier"`) wrapping `Box<dyn Verifier>`. The public `VcCoreVerifier` TS wrapper in `types/vc/core/verifier.ts` unwraps `didResolver.inner`. Exposes `verifyPresentation`, `obtainCredentialStatus`. Also ships a deprecated `create_verifier` factory. |
| `status_issuer.rs` | `VCCoreStatusIssuer` — raw NAPI class (`js_name = "_VcCoreStatusIssuer"`) wrapping `Box<dyn StatusIssuer>`. The public `VcCoreStatusIssuer` TS wrapper in `types/vc/core/status-issuer.ts` applies `contextEnsuredKms`. Exposes `issueStatusList`. Also ships a deprecated `create_status_issuer` factory. |
| `error.rs` | Maps `CoreError` variants to `EncodableError` using the `JsError` string enum. |

## Key types / traits
- `VcCoreIssuer` (TS wrapper) / `_VcCoreIssuer` (raw NAPI) — Protocol-agnostic issuer; supports one-shot `issueCredential` and the two-step `prepareCredential` → `VCCoreCredentialSigner.signCredential` split.
- `VCCoreCredentialSigner` (TS wrapper in `types/vc/core/signer.ts`) / `_VCCoreCredentialSigner` (raw NAPI) — Stand-alone signer for the prepare/sign split.
- `VcCoreHolder` (TS wrapper) / `_VcCoreHolder` (raw NAPI) — Protocol-agnostic holder API with vault integration.
- `VcCoreVerifier` (TS wrapper) / `_VcCoreVerifier` (raw NAPI) — Protocol-agnostic verifier API.
- `VcCoreStatusIssuer` (TS wrapper) / `_VcCoreStatusIssuer` (raw NAPI) — Status list issuer API.
- `JsCredential`, `JsPresentation` — Core VC payload types.
- `JsIssuerMetadata`, `JsHolderMetadata` — Service configuration types.
- `UnsignedCredential` (TS type, shared from `wrappers/types/vc/unsigned-credential.ts`) — externally-tagged wire shape exchanged between `prepareCredential` and `signCredential`.

## Dependencies
- Depends on: `agent_sdk::vc::core` (including `CredentialSigner`, `UnsignedCredential`, and the `PrepareCredential` / `SignCredential` traits), `agent_sdk::vc` (credential/presentation types), `agent_sdk::nonce`, `crate::kms::JsKms`, `crate::vault::JsVault`, `crate::did::JsUniversalDIDResolver`, `crate::http::ReqwestHttpClient`, `crate::vc::status_formats`, `crate::utils::{from_json_object, to_json_object}`
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vc::mod`, `crate::inmem::vault`
