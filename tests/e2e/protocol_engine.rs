use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::didcomm::agent::{Agent, AgentConfig};
use agent_sdk::didcomm::connection::in_mem::InMemConnectionService;
use agent_sdk::didcomm::protocol::outofband::{InvitationConfig, OutOfBandV2Protocol};
use agent_sdk::didcomm::protocol::tictactoe::fsm::state::TicTacToeState;
use agent_sdk::didcomm::protocol::tictactoe::message::{Mark, Move};
use agent_sdk::didcomm::protocol::tictactoe::protocol::TicTacToeProtocol;
use agent_sdk::didcomm::transport::http::HttpTransport;
use agent_sdk::inmem::kms::{KeyHandle, LocalKms};
use agent_sdk::inmem::storage::InMemStorage;
use agent_sdk::kms::KeyType;
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use url::Url;
use uuid::Uuid;

#[tokio::test]
async fn test_tic_tac_toe() {
    // Create agent config
    let alice_config = AgentConfig {
        domain: Url::parse("http://alice-agent.example.com").unwrap(),
        endpoint: Url::parse("http://127.0.0.1:8000").unwrap(),
        label: "Alice Agent".to_string(),
        didcomm_scheme: Some("didcomm".to_string()),
    };

    let alice_agent = setup_agent(alice_config);
    let alice_oob_protocol = setup_oob_protocol(&alice_agent).await;
    let alice_tic_tac_toe_protocol = setup_tic_tac_toe_protocol(&alice_agent).await;

    let bob_config = AgentConfig {
        domain: Url::parse("http://bob-agent.example.com").unwrap(),
        endpoint: Url::parse("http://127.0.0.1:8001").unwrap(),
        label: "Bob Agent".to_string(),
        didcomm_scheme: Some("didcomm".to_string()),
    };

    let bob_agent = setup_agent(bob_config);
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

    let game_id = Uuid::new_v4().to_string();

    let (alice_subscription, alice_observable) = alice_tic_tac_toe_protocol
        .events()
        .observe(game_id.to_owned())
        .await;

    let (bob_subscription, bob_observable) = bob_tic_tac_toe_protocol
        .events()
        .observe(game_id.to_owned())
        .await;

    alice_agent.start().await.unwrap();
    bob_agent.start().await.unwrap();

    bob_tic_tac_toe_protocol
        .start_game(
            game_id.to_owned(),
            bob_connection,
            Move::new(Mark::X, "B2").unwrap(),
            Some("Lets play!".to_string()),
        )
        .await
        .unwrap();

    println!("Game started: {game_id}");

    let state = alice_observable.next().await.unwrap();
    println!("Alice's game state changed to: {:?}", state);
    let state = bob_observable.next().await.unwrap();
    println!("Bob's game state changed to: {:?}", state);
    println!("===============================================================");

    alice_tic_tac_toe_protocol
        .send_move(
            game_id.to_owned(),
            Move::new(Mark::O, "C1").unwrap(),
            Some("Sure!".to_string()),
        )
        .await
        .unwrap();

    let state = alice_observable.next().await.unwrap();
    println!("Alice's game state changed to: {:?}", state);
    let state = bob_observable.next().await.unwrap();
    println!("Bob's game state changed to: {:?}", state);
    println!("===============================================================");

    bob_tic_tac_toe_protocol
        .send_move(game_id.to_owned(), Move::new(Mark::X, "B1").unwrap(), None)
        .await
        .unwrap();

    let state = alice_observable.next().await.unwrap();
    println!("Alice's game state changed to: {:?}", state);
    let state = bob_observable.next().await.unwrap();
    println!("Bob's game state changed to: {:?}", state);
    println!("===============================================================");

    alice_tic_tac_toe_protocol
        .send_move(game_id.to_owned(), Move::new(Mark::O, "C2").unwrap(), None)
        .await
        .unwrap();

    let state = alice_observable.next().await.unwrap();
    println!("Alice's game state changed to: {:?}", state);
    let state = bob_observable.next().await.unwrap();
    println!("Bob's game state changed to: {:?}", state);
    println!("===============================================================");

    bob_tic_tac_toe_protocol
        .send_move(
            game_id.to_owned(),
            Move::new(Mark::X, "B3").unwrap(),
            Some("I win, good game!".to_string()),
        )
        .await
        .unwrap();

    let state = alice_observable.next().await.unwrap();
    println!("Alice's game state changed to: {:?}", state);
    let state = bob_observable.next().await.unwrap();
    println!("Bob's game state changed to: {:?}", state);
    println!("===============================================================");

    alice_tic_tac_toe_protocol
        .send_outcome(game_id.to_owned(), Some("Ok, good game!".to_string()))
        .await
        .unwrap();

    let state = alice_observable.next().await.unwrap();
    println!("Alice's game state changed to: {:?}", state);
    let state = bob_observable.next().await.unwrap();
    println!("Bob's game state changed to: {:?}", state);
    println!("===============================================================");

    alice_tic_tac_toe_protocol
        .events()
        .off(game_id.to_owned(), alice_subscription)
        .await;

    bob_tic_tac_toe_protocol
        .events()
        .off(game_id, bob_subscription)
        .await;

    alice_agent.stop().await.unwrap();
    bob_agent.stop().await.unwrap();
}

async fn setup_oob_protocol(
    agent: &Agent<LocalKms, KeyHandle, InMemConnectionService>,
) -> OutOfBandV2Protocol<LocalKms, KeyHandle, InMemConnectionService> {
    let protocol = OutOfBandV2Protocol::new(agent);

    agent.register_protocol(protocol.clone()).await.unwrap();

    protocol
}

async fn setup_tic_tac_toe_protocol(
    agent: &Agent<LocalKms, KeyHandle, InMemConnectionService>,
) -> TicTacToeProtocol<InMemStorage<String, TicTacToeState>> {
    let states_storage = InMemStorage::<String, TicTacToeState>::new();

    let protocol = TicTacToeProtocol::new(agent, states_storage);

    agent.register_protocol(protocol.clone()).await.unwrap();

    protocol
}

pub fn setup_agent(config: AgentConfig) -> Agent<LocalKms, KeyHandle, InMemConnectionService> {
    let kms = LocalKms::new();
    let did_resolver = UniversalResolver::default();

    let http_transport = HttpTransport::new(
        config.endpoint.clone(),
        ReqwestClientBuilder::new().insecure().build().unwrap(),
    );

    let connection_service = InMemConnectionService::new();

    Agent::new(
        config,
        kms,
        did_resolver,
        connection_service,
        http_transport.clone(),
        http_transport,
    )
}
