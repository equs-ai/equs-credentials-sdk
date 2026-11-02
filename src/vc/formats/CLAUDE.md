# formats — Context

## Purpose
Houses all Verifiable Credential format implementations (SD-JWT, W3C JSON-LD, ISO mso_mdoc) plus the shared `API` trait and `Error` type that unify them.

## Files

| File | Role |
|------|------|
| mod.rs | Generic `API` trait, `HasClaims`, `HasCredential`, `IsExpired`, `IsValid`, `GetDateTimeClaim` traits, shared `Error` and `VerifyOptions`. |
| vc.rs | `VCFormat` enum and `HasVCFormat` trait (JwtVcJson, JwtVcJsonLD, LdpVc, SdJwtVc, MsoMdoc). |
| vp.rs | `VPFormat` enum and `HasVPFormat` trait (SdJwtVp, JwtVp, LdpVp, MsoMdoc). |
| json_ld_vc.rs | W3C JSON-LD VC implementation: `JsonLdAPI`, `VC`, `VP`, `VCMetadata` using `ssi` data-integrity suites. `verify_vp` checks the presentation proof and every embedded credential's proof (expiry stays with `IsExpired`, so callers report `CredentialExpired`), requires every credential subject `id` to be the DID that signed the presentation, and, given a `HolderBinder`, requires each presentation proof's `challenge` and `domains` to carry its nonce and verifier id. A V2 presentation without its own proof is accepted only when every credential is BBS-signed; it carries no holder binding. |
| sd_jwt_vc.rs | SD-JWT VC implementation: `SdJwtAPI`, `VCMetadata`, `SignerWrapper`, selective disclosure via `sd_jwt_rs`. `verify_vc` resolves the signing key from a DID URL `kid`, else an `x5c` chain validated against `VerifyOptions.trusted_certs` (native only; with `VerifyOptions.anchor_policy = IntegrityOnly` only for integrity, and no anchor is required), else a `kid`/`iss` DID; `verify_vp` resolves it through `DelegatingKeyResolver`, and with `delegate-sd-jwt` rejects a presentation carrying a delegation chain (it serves verifiers that did not request delegation). `issuer_signed_claims` decodes the issuer-signed claims alone, with no delegate payload; every revocation status check reads `status` from them. |
| dsd_jwt.rs | Delegate SD-JWT (dSD-JWT/dSD-JWT+KB) format primitives — gated `delegate-sd-jwt`. `verify_dsd_jwt` with `DsdJwtPurpose::Delegation` returns the issuer-signed claims and each hop's payloads apart; `DsdJwtPurpose::Presentation` returns `sd_jwt_rs`'s layered claims and no verification entry point uses it. |
| mso_mdoc.rs | ISO 18013-5 mDoc implementation: `MsoMdocAPI`, `Presentation` (CBOR base64url + optional encryption key). Passes the trusted IACA PEMs to one-core, which validates the Document Signer chain up to one of them; with `AnchorPolicy::Require` and no configured anchor (`None` or empty) the anchor check is **skipped** in `verify_vp` itself (developer decision). `verify_vp_with_issuer` also returns the issuer chain and the MSO status (`MdocStatus`, from one-core's `DetailCredential.status`), for the first document only (it warns when there are more); `status_unverified` reads the status without verifying; under `AnchorPolicy::IntegrityOnly` one-core checks the chain's links and validity, `verify_vp_with_issuer` then rejects a self-signed Document Signer (`verify_chain_integrity`, as for an SD-JWT VC's `x5c`), and the caller evaluates issuer trust, which is how the OID4VP verifier uses it, so there an mdoc without anchors is `not_evaluated/no_anchors_configured` and fails under `Enforce`. Its tests' presentation, `tests::sample_mso_mdoc_vp()`, is generated per call through `test_fixtures::mdoc` under a fresh IACA → DS chain and bound to its nonce and `https://verifier.example.com`; the OID4VP verifier tests reuse it. |

## Key types / traits
- `API<CL, C, P, CM, PM, VR>` — async trait: `create_vc`, `create_vp`, `verify_vc`, `verify_vp`.
- `HasClaims<CL>` — `parse_claims()` and `has_type()`. For SD-JWT, `parse_claims` is
  **feature-gated**: without `delegate-sd-jwt` it resolves only the issuer SD-JWT's claims
  (`decode_sd_jwt`); with `delegate-sd-jwt` it uses `decode_dsd_jwt` and adds each dSD-JWT
  chain link's `delegate_payload` claims to the issuer claims (chain order), so delegate-injected
  claims (e.g. `purchase_id`) are visible to discovery/DCQL value-matching. A delegate payload
  never replaces a claim the issuer-signed JWT carries. Unverified either way
  (selection/indexing only; the Verifier re-verifies the chain).
- `HasCredential<C>` — `get_credential()` from a VP.
- `VCFormat` / `VPFormat` — format identification enums.

## Dependencies
- Depends on: `ssi`, `sd_jwt_rs`, `one_core` (mso_mdoc, non-wasm), `one_core_portable`, `crate::crypto`, `crate::did::universal`, `crate::vc::claims`, `crate::vc::status_formats`, `test_fixtures` (tests only: SD-JWT issuer-identifier fixtures, the mdoc test presentation and its IACA → DS chain)
- Used by: `crate::vc::core`, `crate::vc::mod` (top-level `Credential` and `Presentation` types)

## Constraints
- `mso_mdoc.rs` is gated with `#[cfg(not(target_arch = "wasm32"))]`.
