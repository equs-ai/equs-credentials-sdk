# holder — Context

## Purpose
Implements the credential holder side of the WACI Aries issuance protocol: parsing an OOB invitation, sending a credential request, receiving and storing the signed credential, and handling rejections.

## Files

| File | Role |
|------|------|
| `mod.rs` | `IssuanceHolder` — public API; `HolderMessages` enum; `MessageHandler` impl |
| `holder_fsm.rs` | `HolderSM` — pure state machine driving transitions between holder states |
| `states.rs` | `IssuanceHolderState` enum and concrete state structs with `From` transition impls |

## Key types / traits
- `IssuanceHolder<KMS, KH, S, C, V>` — stateful holder; generic over KMS, storage, connection service, and vault
- `HolderSM<KMS, KH, C, V>` — drives `OfferReceived → RequestSent → Finished` transitions
- `IssuanceHolderState` — `OfferReceived`, `RequestSent`, `Finished`
- `HolderMessages` — typed messages: `CredentialOffer`, `CredentialRequestSend`, `Credential`, `ProblemReport`, `CredentialRejectSend`

## Dependencies
- Depends on: `issuance::message`, `issuance::protocol::IssuanceProtocol`, `outofband::OutOfBandV2Protocol`, `crate::vault`, `crate::kms`
- Used by: `issuance::protocol::IssuanceProtocol::new_with_holder`

## Constraints
- An offer it cannot turn into a request, or a credential it cannot store, gets an `invalid-credential-offer` / `invalid-credential` problem report with a fixed comment; the error is logged locally, never sent to the issuer.
- The credential request names the holder's DID as the first subject's `id`; an offer whose subject `id` is anything else is rejected.
