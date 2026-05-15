# tictactoe — Context

## Purpose
A complete example DIDComm protocol implementation of TicTacToe, demonstrating the state-machine-driven protocol pattern with move validation, event emission, and two-player game logic.

## Files

| File | Role |
|------|------|
| `mod.rs` | Module root: `TicTacToeGame` struct, `Error` enum, move validation, winner detection |
| `message.rs` | Message body types: `Move`, `Mark`, `MoveMessageBody`, `OutcomeMessageBody` |
| `protocol.rs` | `TicTacToeProtocol<S>` — high-level API (start game, send move, send outcome); implements `Protocol` |
| `fsm/` | Finite state machine: events, states, `TicTacToeStateMachine` |

## Key types / traits
- `TicTacToeGame` — mutable board state with `make_move`, `apply_moves`, `winner`
- `TicTacToeProtocol<S>` — user-facing protocol handle; generic over `Storage<String, TicTacToeState>`
- `TicTacToeEvent` / `TicTacToeState` — FSM primitives (in `fsm/`)

## Dependencies
- Depends on: `crate::didcomm::agent::Agent`, `crate::didcomm::service::DIDCommService`, `crate::storage::Storage`, `core::protocol::StatefulMessageHandler`
- Used by: application code and tests; registered with `Agent::register_protocol`

## Constraints
- Non-wasm only (lives under `src/didcomm/protocol/`)
