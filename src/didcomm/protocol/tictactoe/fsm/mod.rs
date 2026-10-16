use async_trait::async_trait;

use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::state_machine::StateMachine;
use crate::didcomm::protocol::tictactoe::fsm::event::TicTacToeEvent;
use crate::didcomm::protocol::tictactoe::fsm::state::TicTacToeState;
use crate::storage::Storage;

pub mod event;
pub mod state;

#[derive(Clone)]
pub struct TicTacToeStateMachine<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    states: S,
}

impl<S> TicTacToeStateMachine<S>
where
    S: Storage<String, TicTacToeState> + Clone + 'static,
{
    pub fn new(states: S) -> Self {
        Self { states }
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
        if let Some(game_id) = thid {
            self.states.get(&game_id).await.map_err(|err| {
                protocol::Snafu {
                    details: err.to_string(),
                }
                .build()
            })
        } else {
            Ok(None)
        }
    }

    async fn process_event(&self, event: Self::Event) -> protocol::Result<TicTacToeState> {
        let current_state = self.state(Some(event.game_id().to_string())).await?;

        let new_state = match event {
            TicTacToeEvent::SendMove {
                game_id,
                from,
                to,
                move_,
            } => match current_state {
                None => TicTacToeState::init_their_move(game_id, from, to, move_),
                Some(TicTacToeState::MyMove(game)) => {
                    TicTacToeState::transit_to_their_move(game, move_)
                }
                _ => protocol::Snafu {
                    details: format!("Illegal send move event: {:?}", move_),
                }
                .fail(),
            },
            TicTacToeEvent::ReceiveMove {
                game_id,
                from,
                to,
                move_,
            } => match current_state {
                None => TicTacToeState::init_my_move(game_id, from, to, move_),
                Some(TicTacToeState::TheirMove(game)) => {
                    TicTacToeState::transit_to_my_move(game, move_)
                }
                _ => protocol::Snafu {
                    details: format!("Illegal receive move event: {:?}", move_),
                }
                .fail(),
            },
            TicTacToeEvent::SendOutcome {
                game_id,
                from,
                to,
                outcome,
            } => {
                let state = current_state.ok_or_else(|| {
                    protocol::Snafu {
                        details: "Illegal outcome event, game is not found",
                    }
                    .build()
                })?;

                TicTacToeState::transit_to_done(state.game().clone(), outcome)
            }
            TicTacToeEvent::ReceiveOutcome {
                game_id,
                from,
                to,
                outcome,
            } => {
                let state = current_state.ok_or_else(|| {
                    protocol::Snafu {
                        details: "Illegal outcome event, game is not found",
                    }
                    .build()
                })?;

                TicTacToeState::transit_to_done(state.game().clone(), outcome)
            }
        }?;

        Ok(new_state)
    }

    async fn change_state(&self, new_state: Self::State) -> protocol::Result<()> {
        self.states
            .put(new_state.game().id.clone(), new_state.clone())
            .await
            .map_err(|err| {
                protocol::Snafu {
                    details: err.to_string(),
                }
                .build()
            })
    }
}
