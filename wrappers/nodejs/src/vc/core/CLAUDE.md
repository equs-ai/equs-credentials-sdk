# vc/core — Context

## Purpose
Provides NAPI-RS bindings for the protocol-agnostic VC core layer, including `VCCoreIssuer`, `VCCoreHolder`, `VCCoreVerifier`, and `VCCoreStatusIssuer`. Also defines all shared data types used across the VC subsystem: credential formats, presentation types, key metadata, proof-of-possession metadata, credential definitions, status information, and status list structures.

## Files

| File | Role |
|------|------|
| `mod.rs` | Defines all shared NAPI types: `JsCredential`, `JsCredentialMetadata`, `JsVCFormat`, `JsAlg`, `JsProof`, `JsCredentialRequest`, `JsCredentialOffer`, `JsCredentialDefinition`, `JsIssuerMetadata`, `JsHolderMetadata`, `JsPresentation`, `JsPresentationInput`, `JsPresentationRestriction`, `JsProofOfPossessionMetadata`, `JsHolderBinder`, `JsCredentialStatusInfo`, `JsVCStatusesData`, `JsStatusList`, `JsVCStatus`, `JsStatusListDefinition`, `JsStatusIssuerMetadata`, and many supporting enums. |
| `issuer.rs` | `VCCoreIssuer` — NAPI class wrapping `Box<dyn Issuer>`. Exposes `offer_credential` and `issue_credential`. Factory function `create_issuer` builds an `IssuerService`. |
| `holder.rs` | `VCCoreHolder` — NAPI class wrapping `Box<dyn Holder>`. Exposes `request_credential`, `store_credential`, `verify_credential`, `create_presentation_auto`, `find_vcs_for_presentation`, `create_presentation`, and `get_credential_status`. Factory function `create_holder` builds a `HolderService`. |
| `verifier.rs` | `VCCoreVerifier` — NAPI class wrapping `Box<dyn Verifier>`. Exposes `verify_presentation` and `obtain_credential_status`. Factory function `create_verifier` builds a `VerifierService`. |
| `status_issuer.rs` | `VCCoreStatusIssuer` — NAPI class wrapping `Box<dyn StatusIssuer>`. Exposes `issue_status_list`. Factory function `create_status_issuer` builds a `StatusIssuerService`. |
| `error.rs` | Maps `CoreError` variants to `EncodableError` using the `JsError` string enum. |

## Key types / traits
- `VCCoreIssuer` — Protocol-agnostic issuer API.
- `VCCoreHolder` — Protocol-agnostic holder API with vault integration.
- `VCCoreVerifier` — Protocol-agnostic verifier API.
- `VCCoreStatusIssuer` — Status list issuer API.
- `JsCredential`, `JsPresentation` — Core VC payload types.
- `JsIssuerMetadata`, `JsHolderMetadata` — Service configuration types.

## Dependencies
- Depends on: `agent_sdk::vc::core`, `agent_sdk::vc` (credential/presentation types), `agent_sdk::nonce`, `crate::kms::JsKms`, `crate::vault::JsVault`, `crate::did::JsUniversalDIDResolver`, `crate::http::ReqwestHttpClient`, `crate::vc::status_formats`
- Used by: `crate::vc::oid4vci`, `crate::vc::oid4vp`, `crate::vc::mod`, `crate::inmem::vault`
