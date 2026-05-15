# common — Context

## Purpose
Houses cross-cutting primitives shared by all Aries protocol implementations: thread correlation structs, completion status, and the `impl_didcomm_message_conversion!` macro.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module re-export |
| `message/` | `Thread`, `Status`, `impl_didcomm_message_conversion!`, `threadlike!` |

## Key types / traits
- `Thread` — DIDComm thread / parent-thread identifiers
- `Status` — terminal outcome of a protocol exchange
- `impl_didcomm_message_conversion!` — derives `TryFrom<Message>` / `TryFrom<T>` for Aries message structs
- `threadlike!` — derives `set_thread`, `set_thread_id`, `set_pthid` setters

## Dependencies
- Depends on: `crate::didcomm::core::envelope::Message`, `crate::didcomm::protocol::aries::problem_report`
- Used by: `issuance`, `present_proof`, `problem_report`, `empty` sub-modules
