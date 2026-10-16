# didcomm::protocol::aries::present_proof::verifier — Context

## Purpose
Implements the Verifier role for Aries Present Proof v3. The Verifier creates a `PresentationRequest`, distributes it via an OOB invitation, receives the Holder's VP, and verifies it using `vc::core::VerifierService`.

## Files

| File | Role |
|------|------|
| `mod.rs` | `Verifier` struct, `MessageHandler` impl, `Protocol` impl, construction logic |
| `state_machine.rs` | `VerifierSM` — drives `VerifierState` transitions |
| `states.rs` | `VerifierState` enum and concrete state structs |

## Key types / traits

### `Verifier<KMS, KH, C, S>`
Generic over KMS, KH, C (connection service), S (state storage for `VerifierState`).

Fields: `agent`, `storage`, `event_emitter`, `oob`, `connection_key_type`, `key_mutex`, `verifier_service`.

### Construction (`Verifier::new`)
1. Creates `VerifierService`.
2. Registers three protocols with the agent: `PresentationProtocol`, `ProblemReportProtocol`, `EmptyProtocol`.

### Public API
```
create_presentation_request(proof_request) → String (ID)
create_invitation(pr_id, config)           → Url
get_state(id)                              → VerifierState
get_presentation_request(id)               → PresentationRequest
step(id, message)                          → ()
observe_state(id)                          → (Subscription, EventObservable<VerifierState>)
```

### State machine (`VerifierSM`)
```
Initiated
  + SendPresentationRequest(connection) → PresentationRequestSent

PresentationRequestSent
  + PresentationReceived(pres)          → Finished (Success) if valid; sends ProblemReport if invalid
  + PresentationRejectReceived(report)  → Finished (Rejected)
  + ProblemReport(report)               → Finished (Rejected)

Finished → Finished (terminal)
```

### States
- `InitialState` — holds `presentation_request`
- `PresentationRequestSentState` — calls `VerifierService::verify_presentation`; sends `ProblemReport` on failure
- `FinishedState` — holds `presentation_request`, optional `presentation`, `status`, `thread`

## Dependencies
- Depends on: `vc::core::VerifierService`, `protocol::outofband::OutOfBandV2Protocol`, `protocol::aries::problem_report`, `protocol::aries::empty`, `crate::didcomm::core::key_mutex::KeyMutex`
- Used by: `present_proof::PresentationProtocol::new_with_verifier`

## Constraints
- Non-wasm only.
