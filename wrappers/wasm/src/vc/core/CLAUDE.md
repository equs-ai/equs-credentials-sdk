# vc/core — Context

## Purpose
Provides wasm-bindgen bindings for the protocol-agnostic VC core layer, including `VcCoreIssuer`, `VcCoreHolder`, `VcCoreVerifier`, and `VcCoreStatusIssuer`. Also defines all WASM-side data types used across the VC subsystem: credential formats, presentation types, key metadata, proof-of-possession metadata, credential definitions, status information, and status list structures.

## Files

| File | Role |
|------|------|
| `mod.rs` | Declares `pub mod signer`, `pub mod types`, and private sub-modules; re-exports the four main classes and `WasmPresentationRestrictionValue`. Also re-exports `pub use ::core::ops` to keep wasm_bindgen-generated `core::ops` paths valid when `core` resolves to this module. |
| `signer.rs` | `VcCoreCredentialSigner` (exported as `VCCoreCredentialSigner` via `js_name`) — wasm-bindgen struct wrapping `Box<dyn SignCredential>`. Constructed from a JS-supplied `Kms` + `UniversalDIDResolver`. Exposes `signCredential(unsigned)` — deserializes the JS object into the externally-tagged `UnsignedCredential` enum and delegates to a `CredentialSigner<JsKeyHandle, JsKms>`. Matches the nodejs/uniffi shape so the same payload works across all wrappers. |
| `types.rs` | Defines all WASM-side serde types. Structs with a single discriminant field use plain `#[serde(rename_all = "camelCase")]`; multi-variant format+payload types use `#[serde(tag = "format", content = "payload", rename_all = "camelCase")]` (adjacently-tagged enums). `WasmProofOfPossessionNotBefore` uses `#[serde(tag = "strategy")]` (internally-tagged). `EmptyPayload {}` is a shared empty struct used as the payload for unit-like variants that must serialize as `{ "payload": {} }` (e.g. `BitstringStatusList`, `StatusListTokenCwt`). Key types: `WasmProof`, `WasmCredentialRequest`, `WasmCredentialDefinition`, `WasmCredentialDefinitionData` (tagged enum), `WasmCredentialOffer`, `WasmCredentialOfferContent` (tagged enum), `WasmCredentialStatusInfo` (tagged enum), `WasmVCStatusesData` (tagged enum), `WasmStatusList` (tagged enum), `WasmStatusListFormat` (tagged enum), `WasmStatusListDefinition`, `WasmStatusIssuerMetadata`, `WasmIssuerMetadata`, `WasmHolderMetadata`, `WasmProofOfPossessionMetadata`, `WasmProofOfPossessionNotBefore` (internally-tagged enum), `WasmHolderBinder`, `WasmPresentation` (tagged enum), `WasmPresentationRestriction`, `WasmPresentationInput`, `WasmPresentationRestrictionValue`. |
| `issuer.rs` | `VcCoreIssuer` — wasm_bindgen class wrapping `Box<dyn IssuerWithPrepare>` (a private combining trait: `Issuer + PrepareCredential`). Constructed via `new VcCoreIssuer(kms, metadata, didResolver)`. Exposes `offerCredential`, `issueCredential`, and `prepareCredential`. `prepareCredential` returns the externally-tagged `UnsignedCredential` JSON shape consumable by `VCCoreCredentialSigner.signCredential`. |
| `holder.rs` | `VcCoreHolder` — wasm_bindgen class wrapping `Box<dyn Holder>`. Constructed via `new VcCoreHolder(kms, vault, metadata, didResolver, httpClient)`. Exposes `requestCredential`, `storeCredential`, `verifyCredential`, `createPresentationAuto`, `findVcsForPresentation`, and `createPresentation`. |
| `verifier.rs` | `VcCoreVerifier` — wasm_bindgen class wrapping `Box<dyn Verifier>`. Constructed via `new VcCoreVerifier(verifierId, didResolver)`. Exposes `verifyPresentation` and `obtainCredentialStatus`. |
| `status_issuer.rs` | `VcCoreStatusIssuer` — wasm_bindgen class wrapping `Box<dyn StatusIssuer>`. Constructed via `new VcCoreStatusIssuer(kms, metadata)`. Exposes `issueStatusList`. |

## Key types / traits
- `VcCoreIssuer` — Protocol-agnostic issuer API; supports both one-shot `issueCredential` and the two-step `prepareCredential` → `VCCoreCredentialSigner.signCredential` split via the `IssuerWithPrepare` combining trait.
- `VcCoreHolder` — Protocol-agnostic holder API with vault integration.
- `VcCoreVerifier` — Protocol-agnostic verifier API.
- `VcCoreStatusIssuer` — Status list issuer API.
- `WasmPresentationRestrictionValue` — Helper enum with `withString`, `withPattern`, `withArray` constructors mirroring the TypeScript class.
- `IssuerWithPrepare` (private) — Combines `Issuer + PrepareCredential` into a single object-safe trait, enabling `prepareCredential` on the boxed issuer service.

## Dependencies
- Depends on: `agent_sdk::vc::core` (including `PrepareCredential`, `SignCredential`, `UnsignedCredential`), `agent_sdk::vc` (credential/presentation types), `crate::kms::JsKms`, `crate::vault::JsVault`, `crate::did::UniversalDIDResolver`, `crate::http::JsHttpClient`, `crate::vc` (shared JS credential types)
- Used by: `crate::vc::mod` (re-exported via `pub mod core`)

## Constraints
- All async trait implementations use `#[async_trait(?Send)]` — the entire crate is single-threaded.
- The Rust structs are named `VcCoreIssuer`, `VcCoreHolder`, etc. directly (not via `js_name`) so the exported JS names match the Node.js wrapper, enabling shared `js_common` tests to work against both packages. Exception: `VcCoreCredentialSigner` uses `#[wasm_bindgen(js_name = "VCCoreCredentialSigner")]` to match the screaming-caps name expected by shared tests.
- `WasmPresentationRestrictionValue.type_` field uses `#[serde(rename = "type")]` (not `"type_"`) to match the TypeScript `InternalPresentationRestrictionValue.type` property.
- Optional complex parameters use `Option<ExternType>` (e.g. `Option<HolderBinder>`). `Option<JsValue>` does NOT work as a wasm_bindgen parameter; `Option<T>` where `T` is a wasm_bindgen extern type works correctly and generates `T | undefined` in TypeScript.
- `prepareCredential` serializes the `UnsignedCredential` using `Serializer::json_compatible()` (via `convert_to_opaque_object_unchecked`) to avoid the `serde_json::Number` internal representation leaking into the JS object.
- All multi-variant format+payload types in `types.rs` are adjacently-tagged enums (`#[serde(tag = "format", content = "payload")]`) rather than plain structs. Unit-like variants use `EmptyPayload {}` as content to preserve `"payload": {}` on the wire. `WasmCredentialOffer.protocol_data` and `WasmCredentialDefinition` fields that use `serde_json::Value` are the only remaining dynamic-JSON fields; everything else is statically typed.
- `verifier.rs` both `verifyPresentation` and `obtainCredentialStatus` accept `http_client: &ReqwestHttpClient`. Tests use a `mockttp` local server so `ReqwestHttpClient.insecure()` can make real HTTP calls against controlled responses.
