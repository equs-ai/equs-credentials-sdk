# didcomm::core — Context

## Purpose
Infrastructure layer beneath the DIDComm agent. Provides envelope cryptography, message routing, protocol registration, and supporting utilities. Nothing here is protocol-specific.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root; re-exports sub-modules and `DIDCommService` |
| `envelope/` | DIDComm V2 pack/unpack via the `didcomm` crate — see [envelope/CLAUDE.md](envelope/CLAUDE.md) |
| `protocol/` | `Protocol` trait, `MessageHandler`, `StateMachine` abstractions — see [protocol/CLAUDE.md](protocol/CLAUDE.md) |
| `protocol_registry.rs` | Runtime registry mapping message types to handlers; shared via `Arc<RwLock<_>>` |
| `dispatcher.rs` | Receives a decoded `Message`, looks up handler in registry, calls `handle` |
| `message_receiver.rs` | Unpacks raw bytes → `Message`; feeds to `DispatcherService` |
| `message_sender.rs` | Packs a `Message` and sends via `OutboundTransport` |
| `message_type.rs` | `MessageType` struct + `parse_message_type` utility |
| `message_id.rs` | `MessageId` newtype (UUID-backed) |
| `event_emitter.rs` | Pub/sub `EventEmitter<K, V>` used by protocols to emit state-transition events |
| `key_mutex.rs` | Per-key async mutex preventing concurrent state mutations in stateful handlers |
| `service.rs` | `DIDCommService` — owns `MessageReceiver`, `MessageSender`, inbound + outbound transports |

## Data flow (inbound)
```
raw bytes
  → MessageReceiver::receive_message
    → EnvelopeService::unpack
      → Message
        → DispatcherService::dispatch
          → ProtocolRegistry::find_handler(type)
            → MessageHandler::handle(msg)
```

## Data flow (outbound)
```
Message + to DID
  → MessageSender::send
    → EnvelopeService::pack_encrypted
      → OutboundMessage
        → OutboundTransport::send_message
```

## Key types / traits
- `EventEmitter<K, V>` — generic pub/sub; `K` is topic key type, `V` is event payload. `.observe(key)` returns `(Subscription, EventObservable<V>)`.
- `KeyMutex` — per-key async `Mutex` map; used by `Verifier` to prevent concurrent state transitions for the same thread ID.
- `MessageType` — structured type URI; `parse_message_type(&str)` splits into `(scheme, family, version, type)`.
- `MessageId` — UUID-backed newtype for DIDComm message IDs.

## Dependencies
- Depends on: `didcomm` crate (via `envelope`), `crate::did::UniversalResolver`, `crate::kms`, `crate::didcomm::transport`
- Used by: `crate::didcomm::agent::Agent`, all `protocol::*` modules

## Constraints
- Non-wasm only.
