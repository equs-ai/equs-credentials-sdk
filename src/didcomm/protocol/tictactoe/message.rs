use serde::{Deserialize, Serialize};
use snafu::ensure;
use std::str::FromStr;
use strum_macros::{Display, EnumString, IntoStaticStr};

use crate::didcomm::protocol::tictactoe::{IllegalMoveSnafu, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Move(String);

impl Move {
    pub fn new(mark: Mark, coordinate: &str) -> Result<Self> {
        let move_ = Move(format!("{}:{}", mark, coordinate));

        move_.validate()?;

        Ok(Move(format!("{}:{}", mark, coordinate)))
    }

    pub fn mark(&self) -> Mark {
        let mark_char = self.0.chars().nth(0).unwrap();

        Mark::from_str(mark_char.to_string().as_str()).unwrap()
    }

    pub fn coordinate(&self) -> &str {
        self.0.split(':').nth(1).unwrap()
    }

    pub fn validate(&self) -> Result<()> {
        let mut chars = self.coordinate().chars();

        let column = chars.nth(0).ok_or_else(|| {
            IllegalMoveSnafu {
                move_: self.clone(),
            }
            .build()
        })?;

        let row = chars.nth(0).ok_or_else(|| {
            IllegalMoveSnafu {
                move_: self.clone(),
            }
            .build()
        })?;

        ensure!(
            ('A'..='C').contains(&column) && ('1'..='3').contains(&row),
            IllegalMoveSnafu {
                move_: self.clone(),
            }
        );

        Ok(())
    }
}

#[derive(EnumString, Display, Debug, Clone, Serialize, Deserialize, IntoStaticStr, PartialEq)]
pub enum Mark {
    X,
    O,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveMessage {
    pub me: Mark,
    pub moves: Vec<Move>, // Array of move strings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

// The "outcome" message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeMessage {
    pub winner: Option<Mark>, // "X", "O", or--in the case of a draw--"none"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}
