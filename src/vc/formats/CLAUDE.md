# formats — Context

## Purpose
Houses all Verifiable Credential format implementations (SD-JWT, W3C JSON-LD, ISO mso_mdoc) plus the shared `API` trait and `Error` type that unify them.

## Files

| File | Role |
|------|------|
| mod.rs | Generic `API` trait, `HasClaims`, `HasCredential`, `IsExpired`, `IsValid`, `GetDateTimeClaim` traits, shared `Error` and `VerifyOptions`. |
| vc.rs | `VCFormat` enum and `HasVCFormat` trait (JwtVcJson, JwtVcJsonLD, LdpVc, SdJwtVc, MsoMdoc). |
| vp.rs | `VPFormat` enum and `HasVPFormat` trait (SdJwtVp, JwtVp, LdpVp, MsoMdoc). |
| json_ld_vc.rs | W3C JSON-LD VC implementation: `JsonLdAPI`, `VC`, `VP`, `VCMetadata` using `ssi` data-integrity suites. |
| sd_jwt_vc.rs | SD-JWT VC implementation: `SdJwtAPI`, `VCMetadata`, `SignerWrapper`, selective disclosure via `sd_jwt_rs`. |
| dsd_jwt.rs | Delegate SD-JWT (dSD-JWT/dSD-JWT+KB) format primitives — gated `delegate-sd-jwt`. |
| mso_mdoc.rs | ISO 18013-5 mDoc implementation: `MsoMdocAPI`, `Presentation` (CBOR base64url + optional encryption key). |

## Key types / traits
- `API<CL, C, P, CM, PM, VR>` — async trait: `create_vc`, `create_vp`, `verify_vc`, `verify_vp`.
- `HasClaims<CL>` — `parse_claims()` and `has_type()`. For SD-JWT, `parse_claims` is
  **feature-gated**: without `delegate-sd-jwt` it resolves only the issuer SD-JWT's claims
  (`decode_sd_jwt`); with `delegate-sd-jwt` it uses `decode_dsd_jwt` and layers each dSD-JWT
  chain link's `delegate_payload` onto the issuer claims (chain order), so delegate-injected
  claims (e.g. `purchase_id`) are visible to discovery/DCQL value-matching. Unverified either
  way (selection/indexing only; the Verifier re-verifies the chain at presentation).
- `HasCredential<C>` — `get_credential()` from a VP.
- `VCFormat` / `VPFormat` — format identification enums.

## Dependencies
- Depends on: `ssi`, `sd_jwt_rs`, `one_core` (mso_mdoc, non-wasm), `one_core_asdk`, `crate::crypto`, `crate::did::universal`, `crate::vc::claims`, `crate::vc::status_formats`
- Used by: `crate::vc::core`, `crate::vc::mod` (top-level `Credential` and `Presentation` types)

## Constraints
- `mso_mdoc.rs` is gated with `#[cfg(not(target_arch = "wasm32"))]`.
