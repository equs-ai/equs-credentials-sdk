# didcomm::protocol::aries::present_proof::message — Context

## Purpose
Contains all message types and event enums for the Present Proof protocol: inbound/outbound DIDComm messages (`Presentation`, `PresentationRequest`, `ProofRequest`) and the role-specific command enums (`HolderMessages`, `VerifierMessages`) used to drive state machines.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports `HolderMessages`, `VerifierMessages`, `Presentation`, `PresentationRequest`, `ProofRequest` |
| `presentation.rs` | `Presentation` message struct (Holder → Verifier); builder and `impl_didcomm_message_conversion!` |
| `presentation_request.rs` | `PresentationRequest` message struct (Verifier → Holder); builder, attachment conversions, unit test |
| `proof_request.rs` | `ProofRequest` — `PresentationDefinition` plus optional `ProofOptions` (each of `challenge`, `domain` optional); attachment conversion both ways, labelled `dif/presentation-exchange/definitions@v1.0` (RFC 0510 `{options, presentation_definition}`, or a bare definition when there are no options) |

## Key types / traits

### `HolderMessages`
Commands consumed by `HolderSM`:
- `PresentationRequestReceived(PresentationRequest)` — inbound from wire
- `RejectPresentationRequest(String)` — caller-initiated rejection
- `PreparePresentation` — trigger auto VP build
- `SetPresentation(Presentation)` — caller provides VP
- `SendPresentation` — send stored VP
- `PresentationRejectReceived(ProblemReport)` — inbound rejection
- `ProblemReport(ProblemReport)` — generic inbound problem report

`TryFrom<Message>` dispatches on message type segment.

### `VerifierMessages`
Commands consumed by `VerifierSM`:
- `SendPresentationRequest(ConnectionRecord)` — initiates flow
- `PresentationReceived(Presentation)` — inbound from wire
- `PresentationRejectReceived(ProblemReport)` — inbound rejection
- `RequestPresentation(ProofRequest)` — internal command
- `ProblemReport(ProblemReport)` — inbound problem report
- `Unknown` — fallback

### `Presentation`
Builder: `Presentation::create()`, `.add_attachment()`, `.set_thread_id()`, `.set_comment()`.
`impl_didcomm_message_conversion!` generates `TryFrom<Message>` / `TryInto<Message>`.

### `PresentationRequest`
`TryFrom<Attachment>` extracts from JSON attachment (parsing OOB invitation).
`TryFrom<PresentationRequest> for Attachment` embeds into OOB invitation.
`impl_didcomm_message_conversion!` for `Message` conversions.

### `ProofRequest`
Wraps `PresentationDefinition` and optional `ProofOptions { challenge, domain }`, each optional as in Aries RFC 0510 (both only RECOMMENDED there). `TryFrom<ProofRequest> for Attachment` sets `format: dif/presentation-exchange/definitions@v1.0` (`DIF_PRESENTATION_EXCHANGE_DEFINITIONS`, the WACI present-proof v3 attachment registry) and writes the RFC 0510 body `{"options", "presentation_definition"}` when options are set, else the bare definition, which holders that predate options read. `TryFrom<&Attachment>` reads the wrapped body (with or without `options`) or a bare definition, JSON or base64, from an attachment with that `format` or none, and rejects any other `format` with `InvalidAttachmentEncoding`. `PresentationRequest::with_proof_options` sets the options on the first attachment, keeping its `id`.

## Dependencies
- Depends on: `aries::common::{Thread, Status}`, `aries::problem_report::ProblemReport`, `crate::vc::presentation_exchange::PresentationDefinition`, `didcomm::Message`, `crate::didcomm::core::envelope`
- Used by: `present_proof::holder`, `present_proof::verifier`

## Constraints
- Non-wasm only.
