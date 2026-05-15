# presentation_exchange — Context

## Purpose
Implements the DIF Presentation Exchange spec: converts a `PresentationDefinition` into presentation inputs, builds `PresentationSubmission` objects, and validates holder credentials and VP tokens against input descriptor constraints.

## Files

| File | Role |
|------|------|
| mod.rs | All PE logic: `split_to_inputs_for_pd`, `prepare_presentation_response`, `resolve_presentation_response`, `validate_against_presentation_definition`, `validate_credential`, `is_valid_vc_type`. Type aliases for all PE spec types. |

## Key types / traits
- `PresentationDefinition`, `InputDescriptor`, `Constraints`, `ConstraintsField` — core PE spec types (re-exported from `openid4vp`).
- `PresentationSubmission`, `DescriptorMap` — submission/response types.
- `ClaimFormat`, `ClaimFormatMap`, `ClaimFormatPayload` — credential format descriptors.
- `SubmissionRequirement` — grouping/selection rules for submission.
- `PresentationResponse` — internal struct pairing serialized presentations with submission metadata.

## Dependencies
- Depends on: `openid4vp::core`, `crate::vc::core::api`, `crate::vc::claims`, `crate::vault`
- Used by: `oid4vp::holder`, `oid4vp::verifier`, `dcql` (StatusSize re-export)
