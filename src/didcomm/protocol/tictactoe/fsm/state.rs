use snafu::ensure;
use std::future::Future;
use std::pin::Pin;
use strum_macros::Display;

use crate::didcomm::core::protocol;
use crate::didcomm::protocol::tictactoe::TicTacToeGame;
use crate::didcomm::protocol::tictactoe::message::{
    Mark, Move, MoveMessageBody, OutcomeMessageBody,
};

type IsDoneFuture = Pin<Box<dyn Future<Output = protocol::Result<bool>> + Send + 'static>>;

type IsDoneFn = dyn Fn(&str, Vec<Move>) -> IsDoneFuture + Send + Sync + 'static;

#[derive(Display, Debug, Clone, PartialEq, Eq)]
pub enum TicTacToeState {
    MyMove(TicTacToeGame),
    TheirMove(TicTacToeGame),
    WrapUp(TicTacToeGame),
    Done(TicTacToeGame, OutcomeMessageBody),
}

impl TicTacToeState {
    pub fn init_my_move(
        game_id: String,
        from: String,
        to: String,
        move_: MoveMessageBody,
    ) -> protocol::Result<TicTacToeState> {
        let me = match move_.me {
            Mark::X => Mark::O,
            Mark::O => Mark::X,
        };

        ensure!(
            move_.moves.len() == 1,
            protocol::Snafu {
                details: format!(
                    "Illegal moves, expected first move but received {:?} moves",
                    move_.moves.len()
                )
            }
        );

        let new_game =
            TicTacToeGame::new(game_id, me, move_.moves[0].clone(), to, from, move_.comment);

        Ok(TicTacToeState::MyMove(new_game))
    }

    pub fn init_their_move(
        game_id: String,
        from: String,
        to: String,
        move_: MoveMessageBody,
    ) -> protocol::Result<TicTacToeState> {
        ensure!(
            move_.moves.len() == 1,
            protocol::Snafu {
                details: format!(
                    "Illegal moves, expected first move but received {:?} moves",
                    move_.moves.len()
                )
            }
        );

        let new_game = TicTacToeGame::new(
            game_id,
            move_.me.clone(),
            move_.moves[0].clone(),
            from,
            to,
            move_.comment.clone(),
        );

        Ok(TicTacToeState::TheirMove(new_game))
    }

    pub fn transit_to_my_move(
        mut game: TicTacToeGame,
        move_: MoveMessageBody,
    ) -> protocol::Result<TicTacToeState> {
        game.apply_moves(move_.moves).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;
        game.set_comment(move_.comment);

        if game.is_done() {
            Ok(TicTacToeState::WrapUp(game))
        } else {
            Ok(TicTacToeState::MyMove(game))
        }
    }

    pub fn transit_to_their_move(
        mut game: TicTacToeGame,
        move_: MoveMessageBody,
    ) -> protocol::Result<TicTacToeState> {
        game.apply_moves(move_.moves).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;
        game.set_comment(move_.comment);

        if game.is_done() {
            Ok(TicTacToeState::WrapUp(game))
        } else {
            Ok(TicTacToeState::TheirMove(game))
        }
    }

    pub fn transit_to_wrap_up(
        mut game: TicTacToeGame,
        move_: MoveMessageBody,
    ) -> protocol::Result<TicTacToeState> {
        game.apply_moves(move_.moves).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;
        game.set_comment(move_.comment);

        Ok(TicTacToeState::WrapUp(game))
    }

    pub fn transit_to_done(
        game: TicTacToeGame,
        outcome: OutcomeMessageBody,
    ) -> protocol::Result<TicTacToeState> {
        Ok(TicTacToeState::Done(game, outcome))
    }

    pub fn game(&self) -> &TicTacToeGame {
        match self {
            TicTacToeState::MyMove(game) => game,
            TicTacToeState::TheirMove(game) => game,
            TicTacToeState::WrapUp(game) => game,
            TicTacToeState::Done(game, _) => game,
        }
    }

    pub fn outcome(&self) -> Option<&OutcomeMessageBody> {
        match self {
            TicTacToeState::Done(_, outcome) => Some(outcome),
            _ => None,
        }
    }
}
