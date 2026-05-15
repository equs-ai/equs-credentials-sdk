# didcomm::agent — Context

## Purpose
Defines `Agent<KMS, KH, C>` — the top-level DIDComm runtime object that owns all services and exposes the public API for starting/stopping the agent, registering protocols, and sending messages.

## Files

| File | Role |
|------|------|
| `mod.rs` | `Agent` struct, `AgentConfig`, `Error` enum, all public methods |
| `test_utils.rs` | Helpers for spinning up mock agents in unit tests (`#[cfg(test)]`) |

## Key types / traits

### `Agent<KMS, KH, C>`
Generic over: KMS (key management), KH (key handle), C (connection service).

### `AgentConfig`
Static configuration: `domain`, `endpoint` (URL), `label`, optional DIDComm scheme.

### Public API
```
new(kms, did_resolver, connection_service, inbound_transport, outbound_transport, config) → Self
start()                                      → Result<()>
stop()                                       → Result<()>
register_protocol(protocol: impl Protocol)   → Result<()>
send_message(msg, connection_id)             → Result<()>
kms()                                        → &KMS
didcomm_service()                            → &DIDCommService
did_resolver()                               → &UniversalResolver
configuration()                              → &AgentConfig
connection_service()                         → &C
```

### `send_message` flow
1. Look up `ConnectionRecord` from `connection_service` by `connection_id`.
2. Populate `msg.from` and `msg.to` from connection.
3. Delegate to `DIDCommService::send_message`.

### `Error`
Snafu enum wrapping: `service::Error`, `protocol_registry::Error`, `connection::Error`.

## Dependencies
- Depends on: `crate::didcomm::core::{DIDCommService, ProtocolRegistry}`, `crate::didcomm::connection::ConnectionService`, `crate::did::UniversalResolver`, `crate::kms`
- Used by: all `protocol::*` modules (they hold a clone of `Agent`), application entry points

## Constraints
- `KMS` must implement `DIDCommKms<KH>`.
- `KMS`, `KH`, `C` must all be `Clone + 'static` for internal async wiring.
- Non-wasm only.
