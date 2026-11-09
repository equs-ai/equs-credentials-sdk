# didcomm::protocol::aries::present_proof — Context

## Purpose
Implements the Aries Present Proof protocol v3.0 (`present-proof/3.0`). Provides both the Verifier and Holder roles, each with a full state machine, connection setup via OOB, and integration with `vc::core` for credential presentation and verification.

## Files

| File | Role |
|------|------|
| `mod.rs` | Shared `Error` enum, `Result` alias, protocol constants |
| `protocol.rs` | `PresentationProtocol` — `Protocol` impl; wires `Verifier` or `PresentationHolder` as handler |
| `message/` | Message types and command enums — see [message/CLAUDE.md](message/CLAUDE.md) |
| `holder/` | `PresentationHolder` role, `HolderSM` state machine — see [holder/CLAUDE.md](holder/CLAUDE.md) |
| `verifier/` | `Verifier` role, `VerifierSM` state machine — see [verifier/CLAUDE.md](verifier/CLAUDE.md) |

## Key types / traits
- `PresentationProtocol` — wraps either a `Verifier` or `PresentationHolder`; registered with `Agent`; routes `PRESENTATION` / `REQUEST_PRESENTATION` / `PROBLEM_REPORT` / `EMPTY` messages.
- `Error` — snafu enum covering: `Agent`, `NotReady`, `InvalidState`, `CreatePresentation`, `DIDCommService`, `Connection`, `Parse`, `Decode`, `DidUrlResolution`, `InvalidProof`, `VerificationFailed`, `Storage`, `OOB`, `InvalidAttachment`, `InvalidAttachmentEncoding`, `NonceGeneration`, `InvalidCredentialRequest`, `PresentationDefinitionParse`, `ReqwestClientBuilder`.

## Protocol constants
```
PROTOCOL_NAME    = "present-proof"
PROTOCOL_VERSION = "3.0"
REQUEST_PRESENTATION = "request-presentation"
PRESENTATION         = "presentation"
```

## Holder binding
Every presentation is bound to the request it answers. `holder_binder` (in `mod.rs`) builds the `HolderBinder` both roles use: the request's `id` as nonce (the VP proof's `challenge`) and the DID the verifier sent the request from (the OOB invitation's `from`) as `verifier_id` (the proof's `domain`). The holder signs with it and the verifier requires it, so a presentation accepted by one verifier, or for one request, is rejected by any other. The wire format carries no extra field: both values are already in the invitation.

A caller that builds its own VP takes the binding from `PresentationHolder::holder_binder` and signs with it before `set_presentation`.

A state stored without `verifier_did` cannot bind: `holder_binder` fails with `InvalidState` on both roles (the verifier before it reads the presentation), and the exchange restarts with a new request. The verifier DID is not recovered from the connection, because completing an inviter's connection gives it a new `my_did`.

## Dependencies
- Depends on: `vc::core::{HolderService, VerifierService}`, `protocol::outofband`, `protocol::aries::{common, problem_report, empty}`, `crate::didcomm::agent`, `crate::kms`, `crate::vault`
- Used by: application code that calls `Verifier::new` or `PresentationHolder::new`

## Constraints
- Non-wasm only.
