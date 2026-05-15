# empty — Context

## Purpose
Implements the Aries "empty" acknowledgement protocol (v1.0), providing the `Empty` message struct used by issuers and verifiers to confirm successful credential or presentation receipt.

## Files

| File | Role |
|------|------|
| `mod.rs` | Protocol constants (`empty/1.0`, `EMPTY` type name) |
| `message.rs` | `Empty` message struct with `ack` ID list and attachment support; `PleaseAck` helper |
| `protocol.rs` | `EmptyProtocol` — `Protocol` impl that delegates to an injected `MessageHandler` |

## Key types / traits
- `Empty` — DIDComm acknowledgement message
- `EmptyProtocol` — registers an ack handler under the `empty` protocol family

## Dependencies
- Depends on: `crate::didcomm::core::envelope`, `crate::didcomm::protocol::aries::common`
- Used by: `issuance::issuer::Issuer`, `present_proof::verifier::Verifier`
