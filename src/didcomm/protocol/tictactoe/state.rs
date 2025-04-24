use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use strum_macros::Display;

use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::StateMachine;
use crate::didcomm::protocol::tictactoe::event::TicTacToeEvent;
use crate::didcomm::protocol::tictactoe::message::Move;
use crate::storage::{Storage, Transaction};

type IsDoneFuture = Pin<Box<dyn Future<Output = protocol::Result<bool>> + Send + 'static>>;

type IsDoneFn = dyn Fn(&str, Vec<Move>) -> IsDoneFuture + Send + Sync + 'static;

#[derive(Display, Debug, Clone, PartialEq, Eq, Hash)]
pub enum TicTacToeState {
    MyMove,
    TheirMove,
    WrapUp,
    Done,
}

#[derive(Clone)]
pub struct TicTacToeStateMachine<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    states: S,
    is_done: Arc<IsDoneFn>,
}

impl<S> TicTacToeStateMachine<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    pub fn new(
        states: S,
        is_done: impl Fn(&str, Vec<Move>) -> IsDoneFuture + Send + Sync + 'static,
    ) -> Self {
        Self {
            states,
            is_done: Arc::new(is_done),
        }
    }

    async fn process_move_event(
        &self,
        game_id: String,
        moves: &[Move],
        current_state: Option<TicTacToeState>,
        allowed: TicTacToeState,
        next_state: TicTacToeState,
    ) -> protocol::Result<TicTacToeState> {
        if current_state.is_none() || current_state == Some(allowed) {
            Ok(if (self.is_done)(&game_id, moves.to_vec()).await? {
                TicTacToeState::WrapUp
            } else {
                next_state
            })
        } else {
            protocol::Snafu {
                details: format!("Illegal move event, current state: {:?}", current_state),
            }
            .fail()
        }
    }
}

#[async_trait]
impl<S> StateMachine for TicTacToeStateMachine<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    type State = TicTacToeState;
    type Event = TicTacToeEvent;

    async fn state(&self, thid: Option<String>) -> protocol::Result<Option<Self::State>> {
        if let Some(thid) = thid {
            self.states.get(&thid).await.map_err(|err| {
                protocol::Snafu {
                    details: err.to_string(),
                }
                .build()
            })
        } else {
            Ok(None)
        }
    }

    async fn process_event(
        &self,
        thid: Option<String>,
        event: Self::Event,
    ) -> protocol::Result<Self::State> {
        let mut transaction = self.states.begin_transaction().await;

        let game_id = thid.clone().ok_or_else(|| {
            protocol::Snafu {
                details: "Thread id is required".to_string(),
            }
            .build()
        })?;

        let current_state = transaction.get(&game_id).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let new_state = match event {
            TicTacToeEvent::SendMove { ref to, ref moves } => {
                self.process_move_event(
                    game_id.to_string(),
                    moves,
                    current_state,
                    TicTacToeState::MyMove,
                    TicTacToeState::TheirMove,
                )
                .await
            }
            TicTacToeEvent::ReceiveMove {
                ref from,
                ref moves,
            } => {
                self.process_move_event(
                    game_id.to_string(),
                    moves,
                    current_state,
                    TicTacToeState::TheirMove,
                    TicTacToeState::MyMove,
                )
                .await
            }
            TicTacToeEvent::SendOutcome { ref to } => Ok(TicTacToeState::Done),
            TicTacToeEvent::ReceiveOutcome { ref from } => Ok(TicTacToeState::Done),
        }?;

        transaction
            .put(game_id.to_owned(), new_state.clone())
            .map_err(|err| {
                protocol::Snafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        Ok(new_state)
    }
}
