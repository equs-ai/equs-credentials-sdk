# Required components to enable protocol flows over DIDComm

This document describes the components required for implementing protocols over DIDComm, with
descriptions of the connections between components and their responsibilities.

## API Layer

### Agent (Struct)

- Provides centralized access to protocol service API.
- Exposes methods to access Connection, KMS, Vault, repositories, etc.
- Enables dependency injection.

### AgentConfig (Struct)

- Contains all configuration parameters for the agent.
- Includes endpoint information and service configurations.

### DIDCommAPI (Struct)

- Main entry point for the DIDComm system.
- Coordinates services and initialization.
- Handles transport registration.

## Core Layer

### MessageReceiver (Struct)

- Handles incoming messages with async methods.
- Coordinates with `EnvelopeService` for unpacking.
- Processes messages through `InboundMessageProcessor`.
- Routes messages to the `Dispatcher`.

### MessageSender (Struct)

- Prepares outbound messages with async methods.
- Coordinates with `EnvelopeService` for packing.
- Applies outbound processing through `OutboundMessageProcessor`.
- Selects the appropriate transport for delivery.
- Emits events for sent messages.

### Dispatcher (Trait)

- Routes messages to appropriate handlers using async methods.
- Manages protocol message flow.
- Emits dispatch-related events.

### DefaultDispatcher (Struct)

- Works with `ProtocolRegistry` to find the protocol that handles a message.

### EnvelopeService (Struct)

- Handles message encryption and decryption.

### Protocol (Trait)

- Defines the protocol interface.
- Creates handlers for protocol-specific messages.

### StatefulProtocol (Trait)

- Extends the `Protocol` interface and provides methods for handling state using an FSM.

### StateMachine (Trait)

- Generic trait for state machines.
- Manages state transitions with type safety.
- Validates transitions.

### ProtocolRegistry (Struct)

- Maintains a registry of supported protocols.
- Thread-safe lookup of protocols.
- Manages protocol versioning.

## Transport Layer

### InboundTransport (Trait)

- Defines the transport interface for listening to incoming messages.

### OutboundTransport (Trait)

- Defines the transport interface for sending outgoing messages.

### HttpTransport (Struct)

- Implements `Transport` for HTTP.
- Handles HTTP connections using async/await.
- Manages endpoint configuration.

## Connection Layer

### ConnectionService (Struct)

- Centralizes connection management.
- Creates and manages connection records.
- Updates connection states.
- Gets a connection record by various identifiers.

### ConnectionRecord (Struct)

- Represents a connection between agents.
- Contains state, DIDs, and metadata.
- Implements serialization/deserialization.
- Contains timestamps for auditing.

### ConnectionState (Enum)

- Enum representing connection states.
- Provides type safety for state transitions.
- Includes variants such as `Invited`, `Requested`, `Responded`, `Complete`.

## Example: implementing a custom protocol

`CustomProtocol` (Struct) implements either the `Protocol` or the `StatefulProtocol` trait.

**`Protocol`**

- Implement the `handle` method to handle protocol-specific DIDComm messages.
- Implement protocol-specific methods.

**`StatefulProtocol`**

- Define the states, events and actions using Rust enums.
- Define the protocol messages.
- Implement `StateMachine` for state transitions:
    - Implement the `state` and `process_event` methods.
- Implement `StatefulProtocol`:
    - Implement the `validate_message` and `on_state_transition` methods.
    - Implement protocol-specific methods.

### Protocol state machine

The Tic Tac Toe reference protocol shows the shape of a `StatefulProtocol`. Its states and
transitions ([`fsm/`](../src/didcomm/protocol/tictactoe/fsm)):

```mermaid
stateDiagram-v2
    [*] --> TheirMove: SendMove (first move)
    [*] --> MyMove: ReceiveMove (first move)
    MyMove --> TheirMove: SendMove
    TheirMove --> MyMove: ReceiveMove
    MyMove --> WrapUp: SendMove wins or fills the board
    TheirMove --> WrapUp: ReceiveMove ends the game
    WrapUp --> Done: SendOutcome
    WrapUp --> Done: ReceiveOutcome
    Done --> [*]
```


## Component interactions

### What `Agent::new` wires together

```mermaid
flowchart TB
    App["Application code"] --> Agent["Agent"]
    Cfg["AgentConfig"] --> Agent
    Agent --> Svc["DIDCommService"]
    Agent --> Reg["ProtocolRegistry"]
    Agent --> CSvc["ConnectionService"]
    Agent --> Kms["Kms"]
    Agent --> Res["UniversalResolver"]
    Svc --> Recv["MessageReceiver"]
    Svc --> Sendr["MessageSender"]
    Svc --> In["InboundTransport"]
    Svc --> Out["OutboundTransport"]
    Recv --> Env["EnvelopeService"]
    Sendr --> Env
    Recv --> Disp["DispatcherService"]
    Disp --> Reg
    Env --> Kms
    Env --> Res
    CSvc --> CRec["ConnectionRecord · ConnectionState"]
```

### Message paths

```mermaid
flowchart TB
    subgraph OUT["Outbound path"]
        direction TB
        P1["Protocol / StatefulProtocol"] --> S1["MessageSender"]
        S1 --> E1["EnvelopeService · pack_encrypted"]
        E1 --> O1["OutboundTransport"]
        O1 --> H1["HttpTransport"]
        S1 --> EM1["EventEmitter · MessageSentEvent"]
    end
    subgraph IN["Inbound path"]
        direction TB
        H2["HttpTransport"] --> I2["InboundTransport"]
        I2 --> R2["MessageReceiver"]
        R2 --> E2["EnvelopeService · unpack"]
        E2 --> D2["Dispatcher · DispatcherService"]
        D2 --> G2["ProtocolRegistry"]
        G2 --> P2["Protocol handler"]
        P2 --> SM2["StateMachine · process_event"]
        SM2 --> ST2["Storage · change_state"]
    end
```

## Tic Tac Toe protocol flows

### Start game

```mermaid
sequenceDiagram
    autonumber
    participant App as Application (Alice)
    participant P as TicTacToeProtocol
    participant SM as TicTacToeStateMachine
    participant St as Storage
    participant MS as MessageSender
    participant Env as EnvelopeService
    participant Out as OutboundTransport
    participant Bob as Bob's agent

    App->>P: start_game(to, first move)
    P->>SM: process_event(SendMove)
    Note over SM: no stored state<br/>init_their_move
    SM->>St: change_state(TheirMove)
    P->>MS: send_message(move message)
    MS->>Env: pack_encrypted(from, to)
    Env-->>MS: packed message
    MS->>Out: send(OutboundMessage)
    Out->>Bob: HTTP POST (DIDComm envelope)
    MS-->>App: MessageSentEvent
```

### Receive your opponent's move

```mermaid
sequenceDiagram
    autonumber
    participant Alice as Alice's agent
    participant In as InboundTransport
    participant MR as MessageReceiver
    participant Env as EnvelopeService
    participant D as DispatcherService
    participant Reg as ProtocolRegistry
    participant P as TicTacToeProtocol
    participant SM as TicTacToeStateMachine
    participant St as Storage
    participant App as Application (Bob)

    Alice->>In: HTTP POST (DIDComm envelope)
    In->>MR: receive_message(packed)
    MR->>Env: unpack(packed)
    Env-->>MR: Message
    MR->>D: dispatch(message)
    D->>Reg: lookup by protocol name + version
    Reg-->>D: TicTacToeProtocol handler
    D->>P: handle(message)
    P->>SM: process_event(ReceiveMove)
    Note over SM: TheirMove -> MyMove<br/>or WrapUp if the game is over
    SM->>St: change_state(new state)
    P-->>App: state event (EventEmitter)
```

### Move

```mermaid
sequenceDiagram
    autonumber
    participant App as Application
    participant P as TicTacToeProtocol
    participant SM as TicTacToeStateMachine
    participant St as Storage
    participant MS as MessageSender
    participant Peer as Opponent's agent

    App->>P: send_move(game_id, move)
    P->>SM: process_event(SendMove)
    SM->>St: state(game_id)
    St-->>SM: MyMove(game)
    Note over SM: transit_to_their_move
    alt move wins or fills the board
        SM->>St: change_state(WrapUp)
        P->>MS: send move message
        MS->>Peer: DIDComm envelope
        App->>P: send_outcome(game_id, outcome)
        P->>SM: process_event(SendOutcome)
        SM->>St: change_state(Done)
        P->>MS: send outcome message
        MS->>Peer: DIDComm envelope
    else game continues
        SM->>St: change_state(TheirMove)
        P->>MS: send move message
        MS->>Peer: DIDComm envelope
    end
```

## See also

- [How to implement a protocol on the Protocol Engine](guidelines/protocol-engine.md)
- Engine source: [`src/didcomm`](../src/didcomm)
- Reference protocol e2e test: [`tests/e2e/protocol_engine.rs`](../tests/e2e/protocol_engine.rs)

