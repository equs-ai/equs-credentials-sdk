pub mod fsm;
pub mod message;
pub mod protocol;

use crate::didcomm::core;
use crate::didcomm::core::envelope::Message;
use crate::didcomm::protocol::tictactoe::message::{Mark, Move, MoveMessageBody};
use crate::didcomm::service;
use crate::storage;
use common_macros::DebugError;
use fsm::event::TicTacToeEvent;
use serde::de::DeserializeOwned;
use snafu::{Location, Snafu, ensure};
use std::collections::HashSet;
const PROTOCOL_NAME: &str = "tictactoe";
const PROTOCOL_VERSION: &str = "1.0";
const MOVE_MESSAGE_TYPE: &str = "move";
const OUTCOME_MESSAGE_TYPE: &str = "outcome";

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Illegal event: {event}"))]
    IllegalEvent { event: TicTacToeEvent },
    #[snafu(display("Illegal move: {move_:?}"))]
    IllegalMove { move_: Move },
    #[snafu(display("Illegal moves: {details}"))]
    IllegalMoves { details: String },
    #[snafu(display("Incorrect connection: {details}"))]
    Connection { details: String },
    #[snafu(display("Game not found: {id}"))]
    GameNotFound { id: String },
    #[snafu(display("Storage error"))]
    Storage {
        source: storage::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Message parsing error"))]
    Parse {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("DIDComm service error"))]
    DIDComm {
        source: service::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Protocol error"))]
    Protocol {
        source: core::protocol::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicTacToeGame {
    id: String,
    message: MoveMessageBody,
    my_did: String,
    opponent_did: String,
}

impl TicTacToeGame {
    pub fn new(
        id: String,
        me: Mark,
        first_move: Move,
        my_did: String,
        opponent_did: String,
        comment: Option<String>,
    ) -> Self {
        TicTacToeGame {
            id,
            message: MoveMessageBody {
                me,
                moves: vec![first_move],
                comment,
            },
            my_did,
            opponent_did,
        }
    }

    pub fn move_message(&self) -> &MoveMessageBody {
        &self.message
    }

    pub fn make_move(&mut self, move_: Move, comment: Option<String>) -> Result<()> {
        ensure!(move_.mark() == self.message.me, IllegalMoveSnafu { move_ });

        self.validate_move(&move_)?;

        self.message.moves.push(move_);
        self.message.comment = comment;

        Ok(())
    }

    fn validate_move(&mut self, move_: &Move) -> Result<()> {
        move_.validate()?;

        ensure!(
            !self
                .message
                .moves
                .iter()
                .any(|existing| existing.coordinate() == move_.coordinate()),
            IllegalMoveSnafu {
                move_: move_.clone()
            }
        );

        Ok(())
    }

    pub fn set_comment(&mut self, comment: Option<String>) {
        self.message.comment = comment;
    }

    pub fn apply_moves(&mut self, mut moves: Vec<Move>) -> Result<()> {
        ensure!(
            moves.len() > 1,
            IllegalMovesSnafu {
                details: "Empty moves"
            }
        );

        let last_move_index = moves.len() - 1;
        let last_move = moves.remove(last_move_index);

        let expected = self.message.moves.to_vec();

        ensure!(
            expected == moves,
            IllegalMovesSnafu {
                details: format!("Expected {:?} moves, but received {:?}", expected, moves)
            }
        );

        let move_before_last = moves.get(last_move_index);

        if let Some(move_before_last) = move_before_last {
            ensure!(
                last_move.mark() != move_before_last.mark(),
                IllegalMoveSnafu { move_: last_move }
            );
        }

        self.validate_move(&last_move)?;

        self.message.moves.push(last_move);

        Ok(())
    }

    pub fn is_done(&self) -> bool {
        self.winner().is_some()
    }

    pub fn winner(&self) -> Option<Mark> {
        let mut x_pos = HashSet::new();
        let mut o_pos = HashSet::new();

        for mv in self.message.moves.as_slice() {
            match mv.mark() {
                Mark::X => {
                    x_pos.insert(mv.coordinate());
                }
                Mark::O => {
                    o_pos.insert(mv.coordinate());
                }
            }
        }

        // All winning lines on a board
        const LINES: [[&str; 3]; 8] = [
            // rows
            ["A1", "A2", "A3"],
            ["B1", "B2", "B3"],
            ["C1", "C2", "C3"],
            // cols
            ["A1", "B1", "C1"],
            ["A2", "B2", "C2"],
            ["A3", "B3", "C3"],
            // diags
            ["A1", "B2", "C3"],
            ["A3", "B2", "C1"],
        ];

        for line in &LINES {
            // If X has any complete line, X wins
            if line.iter().all(|&c| x_pos.contains(c)) {
                return Some(Mark::X);
            }
            // If O has a complete line, O wins
            if line.iter().all(|&c| o_pos.contains(c)) {
                return Some(Mark::O);
            }
        }

        // No winner yet
        None
    }
}

trait TicTacToeDIDCommMessage {
    fn game_id(&self) -> core::protocol::Result<String>;

    fn recipient(&self) -> core::protocol::Result<String>;

    fn sender(&self) -> core::protocol::Result<String>;

    fn payload<T>(&self) -> core::protocol::Result<T>
    where
        T: DeserializeOwned;
}

impl TicTacToeDIDCommMessage for Message {
    fn game_id(&self) -> core::protocol::Result<String> {
        self.thid.as_ref().map(ToOwned::to_owned).ok_or_else(|| {
            crate::didcomm::core::protocol::Snafu {
                details: "Incorrect message, missing 'thid'".to_string(),
            }
            .build()
        })
    }

    fn recipient(&self) -> core::protocol::Result<String> {
        self.to
            .to_owned()
            .and_then(|to| to.into_iter().nth(0))
            .ok_or_else(|| {
                core::protocol::Snafu {
                    details: "Incorrect message, missing 'recipient'".to_string(),
                }
                .build()
            })
    }

    fn sender(&self) -> core::protocol::Result<String> {
        self.from.to_owned().ok_or_else(|| {
            core::protocol::Snafu {
                details: "Incorrect message, missing 'sender'".to_string(),
            }
            .build()
        })
    }

    fn payload<T>(&self) -> core::protocol::Result<T>
    where
        T: DeserializeOwned,
    {
        serde_json::from_value::<T>(self.body.clone()).map_err(|err| {
            core::protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

#[cfg(test)]
mod tests {
    use url::Url;
    use uuid::Uuid;

    use crate::didcomm::agent::test_utils::setup_agent;
    use crate::didcomm::agent::{Agent, AgentConfig};
    use crate::didcomm::connection::in_mem::InMemConnectionService;
    use crate::didcomm::protocol::outofband::{InvitationConfig, OutOfBandV2Protocol};
    use crate::didcomm::protocol::tictactoe::fsm::state::TicTacToeState;
    use crate::didcomm::protocol::tictactoe::message::{Mark, Move};
    use crate::didcomm::protocol::tictactoe::protocol::TicTacToeProtocol;
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::inmem::storage::InMemStorage;
    use crate::kms::KeyType;

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
}
