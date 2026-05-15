# didcomm::connection — Context

## Purpose
Defines the `ConnectionService` trait and all associated connection data types. A connection represents a pairwise DIDComm relationship between two agents; the module tracks state transitions from `Initial` → `Invited` / `Accepted` → `Completed` or `Abandoned`.

## Files

| File | Role |
|------|------|
| `mod.rs` | `ConnectionService` trait, `ConnectionRecord`, `ConnectionState`, `ConnectionRole`, `CreateOptions`, `Invitation`, `ConnectionQuery`, `Error` |
| `in_mem.rs` | `InMemConnectionService` — in-memory implementation (`#[cfg(any(test, feature = "in-memory"))]`) |
| `test_utils.rs` | Test helpers |

## Key types / traits

### `ConnectionService`
```
create_connection(my_did, create_options) → Result<ConnectionRecord>
update_connection(connection)             → Result<()>
get_connection(id)                        → Result<ConnectionRecord>
```

### `ConnectionRecord`
Serializable per-connection record: `id`, `state`, `role`, `my_did`, `their_did` (Option), `auto_accept`, `thread_id`, `parent_thread_id`, `their_endpoint`, `label`, `alias`, `metadata`, `created_at`, `updated_at`.

`their_did()` returns `Err(ConnectionNotCompleted)` when `their_did` is `None`.

### `ConnectionState`
`Initial | Invited | Accepted | Abandoned | Completed` — `Display` (lowercase), `Default` (`Initial`).

### `ConnectionRole`
`Inviter | Invitee`.

### `CreateOptions`
`{ role, state, label, alias, auto_accept, pthid, metadata }` — fields required at connection creation.

### `Error` variants
`Storage`, `ConnectionNotFound { id }`, `ConnectionNotCompleted`.

## Dependencies
- Depends on: `crate::storage::Storage` (backing `InMemConnectionService`), `crate::did` (for `DID` type)
- Used by: `crate::didcomm::agent::Agent`, `protocol::outofband`, `protocol::aries::*` (all roles)

## Constraints
- Non-wasm only.
- `InMemConnectionService` is gated by `#[cfg(any(test, feature = "in-memory"))]`.
