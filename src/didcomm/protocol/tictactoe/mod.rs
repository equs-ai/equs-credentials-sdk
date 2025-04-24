mod event;
pub mod message;
pub mod protocol;
pub mod state;

use crate::didcomm::core;
use crate::didcomm::core::envelope::Message;
use crate::didcomm::protocol::tictactoe::event::TicTacToeEvent;
use crate::didcomm::protocol::tictactoe::message::{Mark, Move, MoveMessage};
use crate::didcomm::service;
use crate::storage;
use common_macros::DebugError;
use serde::de::DeserializeOwned;
use snafu::{ensure, Location, Snafu};
use std::collections::HashSet;

pub const PROTOCOL_NAME: &str = "tictactoe";
pub const PROTOCOL_VERSION: &str = "1.0";
pub const MOVE_MESSAGE_TYPE: &str = "move";
pub const OUTCOME_MESSAGE_TYPE: &str = "outcome";

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

#[derive(Debug, Clone)]
pub struct TicTacToeGame {
    id: String,
    message: MoveMessage,
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
            message: MoveMessage {
                me,
                moves: vec![first_move],
                comment,
            },
            my_did,
            opponent_did,
        }
    }

    pub fn move_message(&self) -> &MoveMessage {
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
