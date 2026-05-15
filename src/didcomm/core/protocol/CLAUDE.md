# didcomm::core::protocol — Context

## Purpose
Defines the `Protocol` trait and the full message handler / state machine abstraction hierarchy used by all DIDComm protocol implementations.

## Files

| File | Role |
|------|------|
| `mod.rs` | `Protocol` trait, `Error` type, `Result` alias, re-exports |
| `message_handler.rs` | `MessageHandler`, `StatefulMessageHandler`, `StatefulMessageHandlerWrapper` |
| `state_machine.rs` | `StateMachine` trait, `Event` marker trait, `StateTransition` |

## Key types / traits

### `Protocol`
```rust
fn protocol_name(&self) -> &'static str;
fn protocol_version(&self) -> &'static str;
fn get_message_handlers(&self) -> Vec<&dyn MessageHandler>;
```
Registered with `ProtocolRegistry`. The dispatcher queries `get_message_handlers()` to find handlers for each incoming message type.

### `MessageHandler`
```rust
fn supported_message_types(&self) -> &[&str];
async fn handle(&self, msg: Message) -> protocol::Result<()>;
```
Simple, stateless handler interface.

### `StatefulMessageHandler`
Higher-level handler managing a `StateMachine`. Default `handle` implementation:
1. `validate_message`.
2. Converts `Message → Event` via `TryFrom`.
3. Calls `trigger_event` which: processes event → new state → optionally sends a reply message → calls `on_state_transition(new_state)` → saves new state.

### `StateMachine`
```rust
type State: Clone + Debug + Send + Sync + 'static;
type Event: Event + 'static;
async fn state(thid) → Result<Option<Self::State>>;
async fn process_event(event) → Result<Self::State>;
async fn change_state(new_state) → Result<()>;
```

### `Event` (marker trait)
Auto-implemented for any type that is `Clone + Debug + Send + Sync` and implements `TryInto<Option<Message>>` and `TryFrom<Message>`.

### `StatefulMessageHandlerWrapper`
Newtype over `Box<dyn StatefulMessageHandler<StateMachine = SM>>` that implements `MessageHandler`. Used when a stateful handler must be stored as `Box<dyn MessageHandler>`.

## Error type
`Error { pub details: String }` — snafu single-variant struct. Created via `protocol::Snafu { details: "..." }.build()`.

## Dependencies
- Depends on: `crate::didcomm::core::envelope::Message`
- Used by: all `protocol::aries::*` and `protocol::basic_message` implementations

## Constraints
- Non-wasm only.
