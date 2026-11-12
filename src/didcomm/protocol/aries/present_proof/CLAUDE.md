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
Every presentation is bound to the request it answers. The verifier's `create_invitation` makes the invitation DID first (`OutOfBandV2Protocol::create_did` / `create_invitation_from`), then sets Aries RFC 0510 proof options on the request's `ProofRequest` attachment: a fresh random `options.challenge` and that DID as `options.domain`. `holder_binder` (in `mod.rs`) builds the `HolderBinder` both roles use from those options: `options.challenge` as nonce, falling back to the request's `id`, and `options.domain` as `verifier_id`, falling back to `verifier_did`, the DID the request came from (the holder's invitation `from`, the verifier's own invitation DID). Both options are optional in RFC 0510, and the domain may be any operational domain (RFC 0510's example is `us.gov/DriversLicense`), so a third-party verifier's domain is accepted as is; a domain that is a DID (`did:` prefix) names a verifier and must be `verifier_did`, so a verifier cannot relay another SDK verifier's request and forward the presentation bound to it. The holder signs with the binder and the verifier requires it, so a presentation accepted by one verifier, or for one request, is rejected by any other.

A caller that builds its own VP takes the binding from `PresentationHolder::holder_binder` and signs with it before `set_presentation`.

A request that cannot be bound (a state stored without `verifier_did`, or a DID domain that is not `verifier_did`) ends the exchange: the holder's `PreparePresentation`, and the verifier on receiving a presentation, send an `invalid-request` problem report with a fixed comment and finish `Failed`. The verifier DID is not recovered from the connection, because completing an inviter's connection gives it a new `my_did`.

## Dependencies
- Depends on: `vc::core::{HolderService, VerifierService}`, `protocol::outofband`, `protocol::aries::{common, problem_report, empty}`, `crate::didcomm::agent`, `crate::kms`, `crate::vault`
- Used by: application code that calls `Verifier::new` or `PresentationHolder::new`

## Constraints
- Non-wasm only.
