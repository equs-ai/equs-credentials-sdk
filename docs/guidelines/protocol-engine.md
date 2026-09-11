# How to implement a protocol based on the Protocol Engine

Steps to follow to implement your own protocol using the DIDComm Protocol Engine.

The engine itself lives in [`src/didcomm`](../../src/didcomm); the
[reference implementations](#reference-implementations) at the end of this document are the shortest
way to see the whole shape of a protocol before writing one.

## 1. Define protocol-specific messages.

Start by defining the messages your protocol speaks. 
Usually you’ll model these as Rust enums/structs that can be (de)serialized to/from JSON.

```ignore
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialOffer {
    #[serde(rename = "id")]
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: CredentialOfferBody,
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}
```

## 2. Implement the Protocol trait.

The protocol struct defines the protocol's name, version, and message handlers that handle protocol-specific messages.

```ignore
#[async_trait]
impl Protocol for IssuanceProtocol {
    fn protocol_name(&self) -> &'static str {
        "issue-credential"
    }

    fn protocol_version(&self) -> &'static str {
        "3.0"
    }

    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler> {
        self.handlers.iter().map(AsRef::as_ref).collect()
    }
}
```

## 3. Implement Message Handlers.

To handle DIDComm messages, implement either the MessageHandler or StatefulMessageHandler trait for the appropriate protocol messages. 
Implementing MessageHandler requires only the handle method, whereas StatefulMessageHandler also requires you to implement the StateMachine trait and its additional methods.


MessageHandler 
```ignore
#[async_trait]
impl<S> MessageHandler for BasicMessageProtocol<S>
where
    S: Storage<String, BasicMessageRecord> + Clone + 'static,
{
    fn supported_message_types(&self) -> &[&str] {
        &["message"]
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        ...
    }
}
```

State Machine

```ignore
#[async_trait]
impl<S> StateMachine for TicTacToeStateMachine<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    type State = TicTacToeState;
    type Event = TicTacToeEvent;

    async fn state(&self, thid: Option<String>) -> protocol::Result<Option<Self::State>> {
        // returns current state
    }

    async fn process_event(&self, event: Self::Event) -> protocol::Result<TicTacToeState> {
        // Process event, change and save state
    }

    async fn change_state(&self, new_state: Self::State) -> protocol::Result<()> {
        // Handles state changes
    }
}
```

StatefulMessageHandler
```ignore
#[async_trait]
impl<S> StatefulMessageHandler for TicTacMessageHandler<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    fn supported_message_types(&self) -> &[&str] {
        &[MOVE_MESSAGE_TYPE, OUTCOME_MESSAGE_TYPE]
    }

    type StateMachine = TicTacToeStateMachine<S>;

    async fn validate_message(&self, message: &Message) -> protocol::Result<()> {
        ...
    }

    async fn send_message(&self, message: Message) -> protocol::Result<()> {
        ...
    }

    fn state_machine(&self) -> &Self::StateMachine {
        &self.state_machine
    }

    async fn on_state_transition(&self, new_state: TicTacToeState) -> protocol::Result<()> {
        self.event_emitter
            .emit(new_state.game().id.clone(), new_state)
            .await;

        Ok(())
    }
}
```

## 4. Configure Agent

You need to configure the agent and start it. The agent contains all the necessary methods to work with DIDComm v2 protocols. 
With the help of the agent it is possible to send messages, use the KMS and DID resolver, and register the protocol.

```ignore
let config = AgentConfig {
    domain: Url::parse("http://government-agent.example.com").unwrap(),
    endpoint: Url::parse("http://127.0.0.1:8010").unwrap(),
    label: "Government Agent".to_string(),
    didcomm_scheme: Some("didcomm".to_string()),
};

let kms = LocalKms::new();
let did_resolver = UniversalResolver::default();

let http_transport = HttpTransport::new(
config.endpoint.clone(),
ReqwestClientBuilder::new().insecure().build().unwrap(),
);

let connection_service = InMemConnectionService::new();

let agent = Agent::new(
    config,
    kms,
    did_resolver,
    connection_service,
    http_transport.clone(),
    http_transport,
);

agent.start();
```

## 5. Register your protocol in the ProtocolRegistry

To be able to receive DIDComm messages for your protocol you must register it with an agent.

```ignore
let issuance_protocol = IssuanceProtocol::new_with_issuer(issuer.clone());
agent
    .register_protocol(issuance_protocol)
    .await
    .context(AgentSnafu)?;
```

## Reference Implementations

- WACI Issuance Protocol v3: [`src/didcomm/protocol/aries/issuance`](../../src/didcomm/protocol/aries/issuance)
- TicTacToe Protocol: [`src/didcomm/protocol/tictactoe`](../../src/didcomm/protocol/tictactoe)
- Basic Message Protocol v2: [`src/didcomm/protocol/basic_message`](../../src/didcomm/protocol/basic_message)
- Out-of-band protocol v2: [`src/didcomm/protocol/outofband`](../../src/didcomm/protocol/outofband)



