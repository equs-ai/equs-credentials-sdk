# dcql — Context

## Purpose
Implements the Digital Credentials Query Language (DCQL) spec: converts DCQL queries into `PresentationInput` constraints, filters credentials by claim-sets, and validates holder credential sets against a full DCQL query object.

## Files

| File | Role |
|------|------|
| mod.rs | All DCQL logic: `split_to_inputs_for_dcql`, `filter_claims_using_claim_sets`, `filter_creds_with_cred_sets`, `validate_credentials`, `resolve_presentation_response`, `prepare_vp_token_response_for_dcql`. |

## Key types / traits
- `DCQL` — re-export of `openid4vp::core::dcql::DCQL`; the root query object.
- `DCQLCredential` — a single credential query entry inside DCQL.
- `DCQLCredentialID` — string identifier for a credential query.
- `NonEmptyVec<T>` — non-empty vector type from `openid4vp::utils`.
- `Error` — module-local snafu error enum (Parse, FormatNotSupported, NotFound, CredentialQueryValidation, CredentialClaimSetValidation, CredentialSetsValidation).

## Dependencies
- Depends on: `openid4vp::core::dcql`, `crate::vc::core` (PresentationInput/Restriction), `crate::vault::CredentialEntry`, `crate::vc::formats`, `crate::vc::claims`
- Used by: `oid4vp::holder`, `oid4vp::verifier`
