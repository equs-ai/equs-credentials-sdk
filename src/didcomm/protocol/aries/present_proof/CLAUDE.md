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

## Dependencies
- Depends on: `vc::core::{HolderService, VerifierService}`, `protocol::outofband`, `protocol::aries::{common, problem_report, empty}`, `crate::didcomm::agent`, `crate::kms`, `crate::vault`
- Used by: application code that calls `Verifier::new` or `PresentationHolder::new`

## Constraints
- Non-wasm only.
