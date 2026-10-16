use async_trait::async_trait;
use snafu::ResultExt;
use std::sync::Arc;

use crate::didcomm::agent::Agent;
use crate::didcomm::connection::{ConnectionRecord, ConnectionService};
use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::event_emitter::EventEmitter;
use crate::didcomm::core::message_sender::SendOptions;
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::core::protocol::message_handler::{
    MessageHandler, StatefulMessageHandler, StatefulMessageHandlerWrapper,
};
use crate::didcomm::core::protocol::state_machine::StateMachine;
use crate::didcomm::protocol::tictactoe;
use crate::didcomm::protocol::tictactoe::fsm::TicTacToeStateMachine;
use crate::didcomm::protocol::tictactoe::fsm::event::TicTacToeEvent;
use crate::didcomm::protocol::tictactoe::fsm::state::TicTacToeState;
use crate::didcomm::protocol::tictactoe::message::{Move, MoveMessageBody, OutcomeMessageBody};
use crate::didcomm::protocol::tictactoe::{
    ConnectionSnafu, GameNotFoundSnafu, MOVE_MESSAGE_TYPE, OUTCOME_MESSAGE_TYPE, PROTOCOL_NAME,
    PROTOCOL_VERSION, ProtocolSnafu, TicTacToeDIDCommMessage, TicTacToeGame,
};
use crate::didcomm::service::DIDCommService;
use crate::kms::{KeyHandle, Kms};
use crate::storage::Storage;

#[derive(Clone)]
pub struct TicTacToeProtocol<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    state_machine: TicTacToeStateMachine<S>,
    service: DIDCommService,
    event_emitter: EventEmitter<String, TicTacToeState>,
    handlers: Vec<Arc<dyn MessageHandler>>,
}

impl<S> TicTacToeProtocol<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    pub fn new<KMS, KH, C>(agent: &Agent<KMS, KH, C>, states: S) -> Self
    where
        KMS: Kms<KH> + Clone,
        KH: KeyHandle,
        C: ConnectionService + Clone,
    {
        let state_machine = TicTacToeStateMachine::new(states);

        let mut protocol = Self {
            state_machine,
            service: agent.didcomm_service().clone(),
            event_emitter: EventEmitter::new(),
            handlers: vec![],
        };

        protocol
            .handlers
            .push(Arc::new(StatefulMessageHandlerWrapper::new(
                protocol.clone(),
            )));

        protocol
    }

    pub async fn start_game(
        &self,
        game_id: String,
        connection: ConnectionRecord,
        move_: Move,
        comment: Option<String>,
    ) -> tictactoe::Result<()> {
        let my_did = connection.my_did;
        let opponent_did = connection.their_did.ok_or_else(|| {
            ConnectionSnafu {
                details: "Opponent DID is not provided",
            }
            .build()
        })?;

        let mut game = TicTacToeGame {
            id: game_id,
            message: MoveMessageBody {
                me: move_.mark(),
                moves: vec![],
                comment: None,
            },
            my_did,
            opponent_did,
        };

        game.make_move(move_, comment)?;

        self.trigger_move(game).await
    }

    pub async fn send_move(
        &self,
        game_id: String,
        move_: Move,
        comment: Option<String>,
    ) -> tictactoe::Result<()> {
        let mut game = self.get_game(&game_id).await?;

        game.make_move(move_, comment)?;

        self.trigger_move(game).await
    }

    async fn trigger_move(&self, game: TicTacToeGame) -> tictactoe::Result<()> {
        let event = TicTacToeEvent::SendMove {
            game_id: game.id.to_owned(),
            from: game.my_did.to_owned(),
            to: game.opponent_did.to_owned(),
            move_: game.move_message().clone(),
        };

        self.trigger_event(event).await.context(ProtocolSnafu)
    }

    pub async fn send_outcome(
        &self,
        game_id: String,
        comment: Option<String>,
    ) -> tictactoe::Result<()> {
        let game = self.get_game(&game_id).await?;

        let outcome_message = OutcomeMessageBody {
            winner: game.winner(),
            comment,
        };

        let event = TicTacToeEvent::SendOutcome {
            game_id: game.id.to_owned(),
            from: game.my_did.to_owned(),
            to: game.opponent_did.to_owned(),
            outcome: outcome_message,
        };

        self.trigger_event(event).await.context(ProtocolSnafu)
    }

    pub fn events(&self) -> EventEmitter<String, TicTacToeState> {
        self.event_emitter.clone()
    }

    pub async fn get_game(&self, game_id: &String) -> tictactoe::Result<TicTacToeGame> {
        self.state_machine
            .state(Some(game_id.clone()))
            .await
            .context(ProtocolSnafu)?
            .map(|state| state.game().clone())
            .ok_or_else(|| {
                GameNotFoundSnafu {
                    id: game_id.to_owned(),
                }
                .build()
            })
    }
}

#[async_trait]
impl<S> Protocol for TicTacToeProtocol<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    fn protocol_name(&self) -> &'static str {
        PROTOCOL_NAME
    }

    fn protocol_version(&self) -> &'static str {
        PROTOCOL_VERSION
    }

    fn get_message_handlers(&self) -> Vec<&dyn MessageHandler> {
        self.handlers.iter().map(AsRef::as_ref).collect()
    }
}

#[async_trait]
impl<S> StatefulMessageHandler for TicTacToeProtocol<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    fn supported_message_types(&self) -> &[&str] {
        &[MOVE_MESSAGE_TYPE, OUTCOME_MESSAGE_TYPE]
    }

    type StateMachine = TicTacToeStateMachine<S>;

    async fn validate_message(&self, message: &Message) -> protocol::Result<()> {
        Ok(())
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
