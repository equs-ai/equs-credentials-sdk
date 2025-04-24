use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use std::marker::PhantomData;
use url::Url;

use crate::did::universal::UniversalResolver;
use crate::didcomm::core::dispatcher::DispatcherService;
use crate::didcomm::core::envelope::{DIDCommKms, EnvelopeService};
use crate::didcomm::core::event_emitter::EventEmitter;
use crate::didcomm::core::message_receiver::{MessageReceiver, MessageReceiverConfig};
use crate::didcomm::core::message_sender::MessageSender;
use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::core::protocol_registry::ProtocolRegistry;
use crate::didcomm::core::{message_sender, protocol_registry};
use crate::didcomm::service;
use crate::didcomm::service::DIDCommService;
use crate::didcomm::transport::{InboundTransport, OutboundTransport};
use crate::kms::{KeyHandle, Kms};

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("DIDComm service error"))]
    DIDCommService {
        source: service::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Protocol Registry error"))]
    ProtocolRegistry {
        source: protocol_registry::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct AgentConfig {
    pub didcomm_scheme: Option<String>,
    pub domain: Url,
    pub endpoint: Url,
    pub label: String,
}

#[derive(Clone)]
pub struct Agent<KMS, KH>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
{
    config: AgentConfig,
    kms: KMS,
    did_resolver: UniversalResolver,
    didcomm_service: DIDCommService,
    protocol_registry: ProtocolRegistry,
    _phantom: PhantomData<KH>,
}

impl<KMS, KH> Agent<KMS, KH>
where
    KMS: DIDCommKms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
{
    pub fn new(
        //TODO: Enable builder
        config: AgentConfig,
        kms: KMS,
        did_resolver: UniversalResolver,
        inbound_transport: impl InboundTransport + Clone + 'static,
        outbound_transport: impl OutboundTransport + Clone + 'static,
    ) -> Self {
        let envelope_service = EnvelopeService::new(kms.clone(), did_resolver.clone());

        let protocol_registry = ProtocolRegistry::new();

        let dispatcher = DispatcherService::new(protocol_registry.clone());

        let message_receiver = MessageReceiver::new(
            envelope_service.clone(),
            dispatcher,
            MessageReceiverConfig::default(),
        );

        let message_sender = MessageSender::new(
            envelope_service,
            outbound_transport.clone(),
            EventEmitter::<&'static str, message_sender::Event>::new(),
            did_resolver.clone(),
        );

        let didcomm_service = DIDCommService::new(
            message_receiver,
            message_sender,
            inbound_transport,
            outbound_transport,
        );

        Self {
            config,
            kms,
            did_resolver,
            didcomm_service,
            protocol_registry,
            _phantom: PhantomData,
        }
    }
}

impl<KMS, KH> Agent<KMS, KH>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
{
    pub async fn start(&self) -> Result<()> {
        self.didcomm_service
            .initialize()
            .await
            .context(DIDCommServiceSnafu)
    }

    pub async fn stop(&self) -> Result<()> {
        self.didcomm_service
            .shutdown()
            .await
            .context(DIDCommServiceSnafu)
    }

    pub async fn register_protocol(&self, protocol: impl Protocol + 'static) -> Result<()> {
        self.protocol_registry
            .register_protocol(protocol)
            .await
            .context(ProtocolRegistrySnafu)
    }

    pub fn kms(&self) -> &KMS {
        &self.kms
    }

    pub fn didcomm_service(&self) -> &DIDCommService {
        &self.didcomm_service
    }

    pub fn did_resolver(&self) -> &UniversalResolver {
        &self.did_resolver
    }

    pub fn configuration(&self) -> &AgentConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use crate::did::universal::UniversalResolver;
    use crate::didcomm::agent::{Agent, AgentConfig};
    use crate::didcomm::connection::{ConnectionRecord, ConnectionService};
    use crate::didcomm::protocol::outofband::{InvitationConfig, OutOfBandV2Protocol};
    use crate::didcomm::protocol::tictactoe::message::{Mark, Move};
    use crate::didcomm::protocol::tictactoe::protocol::TicTacToeProtocol;
    use crate::didcomm::protocol::tictactoe::state::TicTacToeState;
    use crate::didcomm::protocol::tictactoe::TicTacToeGame;
    use crate::didcomm::transport::http::HttpTransport;
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::inmem::storage::InMemStorage;
    use crate::kms::KeyType;
    use crate::reqwest::builder::ReqwestClientBuilder;
    use url::Url;

    #[tokio::test]
    async fn test_tic_tac_toe() {
        // Create agent config
        let alice_config = AgentConfig {
            domain: Url::parse("http://alice-agent.example.com").unwrap(),
            endpoint: Url::parse("http://127.0.0.1:8000").unwrap(),
            label: "Alice Agent".to_string(),
            didcomm_scheme: Some("didcomm".to_string()),
        };

        let alice_agent = setup_agent(alice_config).await;
        let alice_oob_protocol = setup_oob_protocol(&alice_agent).await;
        let alice_tic_tac_toe_protocol = setup_tic_tac_toe_protocol(&alice_agent).await;

        let bob_config = AgentConfig {
            domain: Url::parse("http://bob-agent.example.com").unwrap(),
            endpoint: Url::parse("http://127.0.0.1:8001").unwrap(),
            label: "Bob Agent".to_string(),
            didcomm_scheme: Some("didcomm".to_string()),
        };

        let bob_agent = setup_agent(bob_config).await;
        let bob_oob_protocol = setup_oob_protocol(&bob_agent).await;
        let bob_tic_tac_toe_protocol = setup_tic_tac_toe_protocol(&bob_agent).await;

        let invitation_config = InvitationConfig {
            key_type: KeyType::P256,
            label: "Alice's Invitation".to_string(),
            goal: "Let's play a tic tac toe!".to_string(),
            goal_code: "play-tic-tac-toe".to_string(),
            attachments: vec![],
        };

        let (invitation_url, _) = alice_oob_protocol
            .create_invitation(invitation_config)
            .await
            .unwrap();

        let invitation = bob_oob_protocol
            .parse_invitation(invitation_url.as_str())
            .unwrap();

        let bob_connection = bob_oob_protocol
            .accept_invitation(invitation, KeyType::P256)
            .await
            .unwrap();

        let (alice_subscription, alice_observable) = alice_tic_tac_toe_protocol
            .events()
            .observe(TicTacToeState::MyMove)
            .await;

        let (bob_subscription, bob_observable) = bob_tic_tac_toe_protocol
            .events()
            .observe(TicTacToeState::MyMove)
            .await;

        alice_agent.start().await.unwrap();
        bob_agent.start().await.unwrap();

        let game_id = bob_tic_tac_toe_protocol
            .start_game(
                bob_connection,
                Move::new(Mark::X, "B2").unwrap(),
                Some("Lets play!".to_string()),
            )
            .await
            .unwrap();

        println!("Game started: {game_id}");

        let game_id = alice_observable.next().await.unwrap();

        let game = alice_tic_tac_toe_protocol.get_game(&game_id).await.unwrap();

        println!("Alice received move message: {:?}", game.move_message());

        alice_tic_tac_toe_protocol
            .send_move(
                game_id,
                Move::new(Mark::O, "C1").unwrap(),
                Some("Sure!".to_string()),
            )
            .await
            .unwrap();

        let game_id = bob_observable.next().await.unwrap();

        let game = bob_tic_tac_toe_protocol.get_game(&game_id).await.unwrap();

        println!("Bob received move message: {:?}", game.move_message());

        bob_tic_tac_toe_protocol
            .send_move(game_id, Move::new(Mark::X, "B1").unwrap(), None)
            .await
            .unwrap();

        let game_id = alice_observable.next().await.unwrap();

        let game = alice_tic_tac_toe_protocol.get_game(&game_id).await.unwrap();

        println!("Alice received move message: {:?}", game.move_message());

        alice_tic_tac_toe_protocol
            .send_move(game_id, Move::new(Mark::O, "C2").unwrap(), None)
            .await
            .unwrap();

        let game_id = bob_observable.next().await.unwrap();

        let game = bob_tic_tac_toe_protocol.get_game(&game_id).await.unwrap();

        println!("Bob received move message: {:?}", game.move_message());

        alice_tic_tac_toe_protocol
            .events()
            .off(TicTacToeState::MyMove, alice_subscription)
            .await;

        let (alice_subscription, alice_observable) = alice_tic_tac_toe_protocol
            .events()
            .observe(TicTacToeState::WrapUp)
            .await;

        bob_tic_tac_toe_protocol
            .send_move(
                game_id,
                Move::new(Mark::X, "B3").unwrap(),
                Some("I win, good game!".to_string()),
            )
            .await
            .unwrap();

        let game_id = alice_observable.next().await.unwrap();

        let game = alice_tic_tac_toe_protocol.get_game(&game_id).await.unwrap();

        println!("Alice received move message: {:?}", game.move_message());

        bob_tic_tac_toe_protocol
            .events()
            .off(TicTacToeState::MyMove, bob_subscription)
            .await;

        let (bob_subscription, bob_observable) = bob_tic_tac_toe_protocol
            .events()
            .observe(TicTacToeState::Done)
            .await;

        alice_tic_tac_toe_protocol
            .send_outcome(game_id, Some("Ok, good game!".to_string()))
            .await
            .unwrap();

        let game_id = bob_observable.next().await.unwrap();

        println!("Bob received outcome message for game: {game_id}");

        alice_tic_tac_toe_protocol
            .events()
            .off(TicTacToeState::WrapUp, alice_subscription)
            .await;

        bob_tic_tac_toe_protocol
            .events()
            .off(TicTacToeState::Done, bob_subscription)
            .await;

        alice_agent.stop().await.unwrap();
        bob_agent.stop().await.unwrap();
    }

    async fn setup_agent(config: AgentConfig) -> Agent<LocalKms, KeyHandle> {
        let kms = LocalKms::new();
        let did_resolver = UniversalResolver::default();

        let http_transport = HttpTransport::new(
            config.endpoint.clone(),
            ReqwestClientBuilder::new().insecure().build().unwrap(),
        );

        Agent::new(
            config,
            kms,
            did_resolver,
            http_transport.clone(),
            http_transport,
        )
    }

    async fn setup_oob_protocol(
        agent: &Agent<LocalKms, KeyHandle>,
    ) -> OutOfBandV2Protocol<
        LocalKms,
        KeyHandle,
        ConnectionService<InMemStorage<String, ConnectionRecord>>,
    > {
        let conn_storage = InMemStorage::<String, ConnectionRecord>::new();
        let connection_service = ConnectionService::new(conn_storage);

        let protocol = OutOfBandV2Protocol::new(agent, connection_service);

        agent.register_protocol(protocol.clone()).await.unwrap();

        protocol
    }

    async fn setup_tic_tac_toe_protocol(
        agent: &Agent<LocalKms, KeyHandle>,
    ) -> TicTacToeProtocol<InMemStorage<String, TicTacToeGame>, InMemStorage<String, TicTacToeState>>
    {
        let games_storage = InMemStorage::<String, TicTacToeGame>::new();
        let states_storage = InMemStorage::<String, TicTacToeState>::new();

        let protocol = TicTacToeProtocol::new(agent, games_storage, states_storage);

        agent.register_protocol(protocol.clone()).await.unwrap();

        protocol
    }
}
