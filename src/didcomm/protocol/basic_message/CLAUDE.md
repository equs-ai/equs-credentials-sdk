# didcomm::protocol::basic_message — Context

## Purpose
Implements the DIDComm Basic Message protocol v2.0 (`basicmessage/2.0/message`). Supports sending a plain-text message to a peer by DID and receiving incoming messages via `MessageHandler`.

## Files

| File | Role |
|------|------|
| `mod.rs` | `BasicMessageProtocol`, `MessageHandler` + `Protocol` impls, all data types |

## Key types / traits

### `BasicMessageProtocol<S>`
Generic over `S: Storage<String, BasicMessageRecord>`.

Created via `BasicMessageProtocol::new(agent, storage)`.

```
send_message(my_did, their_did, content, options) → String (message_id)
```
1. Builds a DIDComm `Message` with type `basicmessage/2.0/message`.
2. Calls `DIDCommService::send_message`.
3. Persists a `BasicMessageRecord` (role: Sender).
4. Emits `MESSAGE_SENT_EVENT`.

`handle(msg)` (inbound):
1. Parses `BasicMessageContent { content }` from body.
2. Emits `MESSAGE_RECEIVED_EVENT`.

The protocol itself is the sole `MessageHandler` (`get_message_handlers()` returns `vec![self]`).

### Data types
- `BasicMessageContent { content: String }`
- `BasicMessageRecord { id, role, thread_id, parent_thread_id, timestamp, content }`
- `Role::Sender { my_did, their_did } | Receiver { my_did, their_did }`
- `Event::MessageReceived { ... } | MessageSent { ... }`
- `SendOptions { thread_id, parent_thread_id }`

## Protocol constants
```
PROTOCOL_NAME          = "basicmessage"
PROTOCOL_VERSION       = "2.0"
MESSAGE_TYPE           = "message"
MESSAGE_RECEIVED_EVENT = "basic-message-received"
MESSAGE_SENT_EVENT     = "basic-message-sent"
```

## Dependencies
- Depends on: `crate::didcomm::core::{DIDCommService, EventEmitter}`, `crate::storage::Storage`
- Used by: application code; no integration dependency from other protocol modules

## Constraints
- Non-wasm only.
