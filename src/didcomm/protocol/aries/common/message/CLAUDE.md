# message — Context

## Purpose
Provides shared message primitives used across all Aries DIDComm protocols: thread correlation, protocol status representation, and a conversion macro that bridges typed message structs with the underlying `didcomm::Message` type.

## Files

| File | Role |
|------|------|
| `mod.rs` | `impl_didcomm_message_conversion!` macro — generates `TryFrom<Message>` and `TryFrom<typed>` impls |
| `thread.rs` | `Thread` struct (`thid`, `pthid`) and `threadlike!` macro for adding thread setters to message types |
| `status.rs` | `Status` enum (Undefined, Success, Failed, Rejected) carried in FSM finished states |

## Key types / traits
- `Thread` — DIDComm thread/parent-thread identifiers
- `Status` — terminal outcome of an issuance or presentation exchange

## Dependencies
- Depends on: `crate::didcomm::protocol::aries::problem_report::message::ProblemReport` (for `Status`)
- Used by: all Aries message structs in `issuance/message/`, `present_proof/message/`, `problem_report/message.rs`
