# didcomm::protocol::aries::present_proof::holder — Context

## Purpose
Implements the Holder role for Aries Present Proof v3. The Holder receives a presentation request (typically embedded in an OOB invitation), prepares a VP, and sends it to the Verifier.

## Files

| File | Role |
|------|------|
| `mod.rs` | `PresentationHolder` struct, `MessageHandler` impl, `Protocol` impl, construction logic |
| `state_machine.rs` | `HolderSM` — drives `PresentationHolderState` transitions |
| `states.rs` | `PresentationHolderState` enum and concrete state structs |

## Key types / traits

### `PresentationHolder<KMS, KH, S, C, V>`
The main role struct. Generic over: KMS (key management), KH (key handle), S (state storage), C (connection service), V (vault for credential retrieval).

Fields: `agent`, `key_metadata`, `source_id`, `storage`, `vault`, `event_emitter`, `oob`, `connection_key_type`, `holder_service`.

### Construction (`PresentationHolder::new`)
1. Parses OOB invitation URL → extracts `PresentationRequest` from first attachment.
2. Accepts OOB invitation → creates `ConnectionRecord`.
3. Stores initial `PresentationHolderState::RequestReceived` state.
4. Creates `HolderService` (wraps KMS + vault).
5. Registers `PresentationProtocol::new_with_holder(self)` with the agent.

### Public API
```
prepare_presentation() → PresentationPrepared state (auto-creates VP)
set_presentation(pres) → sets manually supplied VP
send_presentation()    → Finished state, sends VP on wire
step(message)          → generic state transition
observe_state()        → (Subscription, EventObservable<PresentationHolderState>)
```

### State machine (`HolderSM`)
```
RequestReceived
  + PreparePresentation        → PresentationPrepared  (auto-creates VP via HolderService)
  + SetPresentation            → PresentationPrepared  (caller supplies VP)
  + RejectPresentationRequest  → Finished

PresentationPrepared
  + SendPresentation           → Finished  (sends Presentation message)
  + RejectPresentationRequest  → Finished

Finished → Finished (terminal)
```

### States
`RequestReceived`, `PresentationPrepared`, `PresentationSent`, `Finished` — each carries `presentation_request`, `connection_id`, `thread`, and where applicable `presentation` or `status`.

## Dependencies
- Depends on: `vc::core::HolderService`, `protocol::outofband::OutOfBandV2Protocol`, `protocol::aries::problem_report`, `protocol::aries::empty`, `crate::kms`, `crate::vault`
- Used by: `present_proof::PresentationProtocol::new_with_holder`

## Constraints
- Non-wasm only.
