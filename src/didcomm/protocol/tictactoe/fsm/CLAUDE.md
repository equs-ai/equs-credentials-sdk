# fsm — Context

## Purpose
Implements the finite state machine for the TicTacToe DIDComm protocol, encoding game state transitions and mapping DIDComm messages to FSM events.

## Files

| File | Role |
|------|------|
| `mod.rs` | `TicTacToeStateMachine` — implements `StateMachine`, persists states, processes events |
| `event.rs` | `TicTacToeEvent` enum (Send/Receive Move/Outcome) with `TryFrom<Message>` / `TryInto<Option<Message>>` |
| `state.rs` | `TicTacToeState` enum (MyMove, TheirMove, WrapUp, Done) with transition helpers |

## Key types / traits
- `TicTacToeStateMachine<S>` — generic over `Storage<String, TicTacToeState>`; implements `StateMachine`
- `TicTacToeEvent` — protocol-level events, convertible to/from `didcomm::Message`
- `TicTacToeState` — persisted game state

## Dependencies
- Depends on: `crate::didcomm::core::protocol::state_machine::StateMachine`, `crate::storage::Storage`, `tictactoe::message`
- Used by: `tictactoe::protocol::TicTacToeProtocol`
