# presentation_exchange — Context

## Purpose
Implements the DIF Presentation Exchange spec: converts a `PresentationDefinition` into presentation inputs, builds `PresentationSubmission` objects, and validates holder credentials and VP tokens against input descriptor constraints.

## Files

| File | Role |
|------|------|
| mod.rs | All PE logic: `split_to_inputs_for_pd`, `prepare_presentation_response`, `resolve_presentation_response`, `validate_against_presentation_definition`, `validate_presented_credential`, `validate_credential`, `is_valid_vc_type`. Type aliases for all PE spec types. |

## Key types / traits
- `PresentationDefinition`, `InputDescriptor`, `Constraints`, `ConstraintsField` — core PE spec types (re-exported from `openid4vp`).
- `PresentationSubmission`, `DescriptorMap` — submission/response types.
- `ClaimFormat`, `ClaimFormatMap`, `ClaimFormatPayload` — credential format descriptors.
- `SubmissionRequirement` — grouping/selection rules for submission.
- `PresentationResponse` — internal struct pairing serialized presentations with submission metadata.
- `validate_presented_credential` — checks the verified claims of one presented credential against every input descriptor through `validate_against_presentation_definition`, with a submission it builds from the VP's own format: an `ldp_vp` as `ldp_vc` at `$.verifiableCredential`, an SD-JWT VP as `dc+sd-jwt` at `$`; any other VP fails with `FormatNotSupported`. Descriptor formats, constraint filters (full JSON Schema) and `submission_requirements` all apply.

## Dependencies
- Depends on: `openid4vp::core`, `crate::vc::core::api`, `crate::vc::claims`, `crate::vault`, `test_fixtures` (tests only: the SD-JWT presentation)
- Used by: `oid4vp::holder`, `oid4vp::verifier`, `dcql` (StatusSize re-export), `didcomm` Aries present-proof (`holder` splits the request's definition, `verifier` runs `validate_presented_credential`)
