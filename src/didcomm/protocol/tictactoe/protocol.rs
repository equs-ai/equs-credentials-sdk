use async_trait::async_trait;
use snafu::ResultExt;
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

use crate::didcomm::agent::Agent;
use crate::didcomm::connection::ConnectionRecord;
use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::event_emitter::EventEmitter;
use crate::didcomm::core::message_sender::SendOptions;
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::{MessageDirection, Protocol, StatefulProtocol};
use crate::didcomm::protocol::tictactoe;
use crate::didcomm::protocol::tictactoe::message::{Mark, Move, MoveMessage, OutcomeMessage};
use crate::didcomm::protocol::tictactoe::state::{TicTacToeState, TicTacToeStateMachine};
use crate::didcomm::protocol::tictactoe::{
    ConnectionSnafu, GameNotFoundSnafu, ParseSnafu, ProtocolSnafu, StorageSnafu,
    TicTacToeDIDCommMessage, TicTacToeGame, MOVE_MESSAGE_TYPE, OUTCOME_MESSAGE_TYPE, PROTOCOL_NAME,
    PROTOCOL_VERSION,
};
use crate::didcomm::service::DIDCommService;
use crate::kms::{KeyHandle, Kms};
use crate::storage::Storage;

#[derive(Clone)]
pub struct TicTacToeProtocol<GS, SS>
where
    GS: Storage<String, TicTacToeGame> + Clone + 'static,
    SS: Storage<String, TicTacToeState> + Clone + 'static,
{
    state_machine: TicTacToeStateMachine<SS>,
    service: DIDCommService,
    games: GS,
    event_emitter: EventEmitter<TicTacToeState, String>,
}

impl<GS, SS> TicTacToeProtocol<GS, SS>
where
    GS: Storage<String, TicTacToeGame> + Clone + 'static,
    SS: Storage<String, TicTacToeState> + Clone + 'static,
{
    pub fn new<KMS, KH>(agent: &Agent<KMS, KH>, games: GS, states: SS) -> Self
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
    {
        let games_storage = games.clone();

        let state_machine =
            TicTacToeStateMachine::new(states, Self::is_done_closure(games.clone()));

        Self {
            state_machine,
            service: agent.didcomm_service().clone(),
            games,
            event_emitter: EventEmitter::new(),
        }
    }

    fn is_done_closure(
        games: GS,
    ) -> impl Fn(
        &str,
        Vec<Move>,
    ) -> Pin<Box<dyn Future<Output = protocol::Result<bool>> + Send + 'static>>
           + Send
           + Sync
           + 'static {
        move |game_id: &str, moves: Vec<Move>| {
            let games = games.clone();
            let game_id = game_id.to_owned();

            Box::pin(async move {
                let game = games.get(&game_id).await.map_err(|err| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;

                if let Some(mut game) = game {
                    game.apply_moves(moves).map_err(|err| {
                        protocol::Snafu {
                            details: err.to_string(),
                        }
                        .build()
                    })?;

                    Ok(game.is_done())
                } else {
                    Ok(false)
                }
            })
        }
    }

    pub async fn start_game(
        &self,
        connection: ConnectionRecord,
        move_: Move,
        comment: Option<String>,
    ) -> tictactoe::Result<String> {
        let my_did = connection.my_did;
        let opponent_did = connection.their_did.ok_or_else(|| {
            ConnectionSnafu {
                details: "Opponent DID is not provided",
            }
            .build()
        })?;

        let mut game = TicTacToeGame {
            id: Uuid::new_v4().to_string(),
            message: MoveMessage {
                me: move_.mark(),
                moves: vec![],
                comment: None,
            },
            my_did,
            opponent_did,
        };

        game.make_move(move_, comment)?;

        let game_id = game.id.to_owned();
        self.process_move(game).await?;

        Ok(game_id)
    }

    pub async fn send_move(
        &self,
        game_id: String,
        move_: Move,
        comment: Option<String>,
    ) -> tictactoe::Result<()> {
        let mut game = self.get_game(&game_id).await?;

        game.make_move(move_, comment)?;

        self.process_move(game).await
    }

    async fn process_move(&self, game: TicTacToeGame) -> tictactoe::Result<()> {
        let message = Message::build(
            Uuid::new_v4().to_string(),
            format!("https://didcomm.org/{PROTOCOL_NAME}/{PROTOCOL_VERSION}/{MOVE_MESSAGE_TYPE}"),
            serde_json::to_value(&game.message).context(ParseSnafu)?,
        )
        .thid(game.id.to_owned())
        .from(game.my_did.to_owned())
        .to(game.opponent_did.to_owned())
        .finalize();

        self.dispatch_message(MessageDirection::Send, message)
            .await
            .context(ProtocolSnafu)?;

        self.games
            .put(game.id.to_owned(), game)
            .await
            .context(StorageSnafu)
    }

    pub async fn send_outcome(
        &self,
        game_id: String,
        comment: Option<String>,
    ) -> tictactoe::Result<()> {
        let game = self.get_game(&game_id).await?;

        let outcome_message = OutcomeMessage {
            winner: game.winner(),
            comment,
        };

        let message = Message::build(
            Uuid::new_v4().to_string(),
            format!(
                "https://didcomm.org/{PROTOCOL_NAME}/{PROTOCOL_VERSION}/{OUTCOME_MESSAGE_TYPE}"
            ),
            serde_json::to_value(&outcome_message).context(ParseSnafu)?,
        )
        .thid(game_id.to_owned())
        .from(game.my_did)
        .to(game.opponent_did)
        .finalize();

        self.dispatch_message(MessageDirection::Send, message)
            .await
            .context(ProtocolSnafu)
    }

    pub fn events(&self) -> EventEmitter<TicTacToeState, String> {
        self.event_emitter.clone()
    }

    pub async fn get_game(&self, game_id: &String) -> tictactoe::Result<TicTacToeGame> {
        self.games
            .get(game_id)
            .await
            .context(StorageSnafu)?
            .ok_or_else(|| {
                GameNotFoundSnafu {
                    id: game_id.to_owned(),
                }
                .build()
            })
    }

    async fn send_message(&self, message: Message) -> protocol::Result<()> {
        let to_did = message.recipient()?;

        self.service
            .send_message(&message, to_did, &SendOptions::default())
            .await
            .map_err(|err| {
                protocol::Snafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    async fn receive_move_message(&self, message: Message) -> protocol::Result<()> {
        let game_id = message.game_id()?;

        let game = self.games.get(&game_id).await.map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let move_message: MoveMessage = message.payload()?;

        let game = if let Some(mut game) = game {
            game.message.moves = move_message.moves.clone();
            game.message.comment = move_message.comment;
            game.opponent_did = message.sender()?;

            game
        } else {
            let me = match move_message.me {
                Mark::X => Mark::O,
                Mark::O => Mark::X,
            };

            TicTacToeGame {
                id: game_id.to_owned(),
                message: MoveMessage {
                    me,
                    moves: move_message.moves.clone(),
                    comment: move_message.comment,
                },
                my_did: message.recipient()?,
                opponent_did: message.sender()?,
            }
        };

        self.games.put(game_id, game.clone()).await.map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(())
    }

    async fn receive_outcome_message(&self, message: Message) -> protocol::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl<GS, SS> Protocol for TicTacToeProtocol<GS, SS>
where
    GS: Storage<String, TicTacToeGame> + Clone + 'static,
    SS: Storage<String, TicTacToeState> + Clone + 'static,
{
    fn protocol_name(&self) -> &'static str {
        PROTOCOL_NAME
    }

    fn protocol_version(&self) -> &'static str {
        PROTOCOL_VERSION
    }

    async fn handle(&self, msg: Message) -> protocol::Result<()> {
        self.dispatch_incoming_message(msg).await
    }
}

#[async_trait]
impl<GS, SS> StatefulProtocol for TicTacToeProtocol<GS, SS>
where
    GS: Storage<String, TicTacToeGame> + Clone + 'static,
    SS: Storage<String, TicTacToeState> + Clone + 'static,
{
    type StateMachine = TicTacToeStateMachine<SS>;

    async fn validate_message(&self, message: &Message) -> protocol::Result<()> {
        let game_id = message.game_id()?;

        let game = self.games.get(&game_id).await.map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        if message.type_.ends_with(OUTCOME_MESSAGE_TYPE) {
            return Ok(());
        }

        let moves = message.payload::<MoveMessage>()?.moves;

        if let Some(mut game) = game {
            game.apply_moves(moves).map_err(|err| {
                protocol::Snafu {
                    details: err.to_string(),
                }
                .build()
            })
        } else {
            Ok(())
        }
    }

    fn state_machine(&self) -> &Self::StateMachine {
        &self.state_machine
    }

    async fn on_state_transition(
        &self,
        old_state: Option<TicTacToeState>,
        new_state: TicTacToeState,
        message_direction: MessageDirection,
        message: Message,
    ) -> protocol::Result<()> {
        let game_id = message.game_id()?;

        match message_direction {
            MessageDirection::Send => self.send_message(message).await?,
            MessageDirection::Receive => match new_state {
                TicTacToeState::Done => self.receive_outcome_message(message).await?,
                _ => self.receive_move_message(message).await?,
            },
        }

        self.event_emitter.emit(new_state, game_id).await;

        Ok(())
    }
}
