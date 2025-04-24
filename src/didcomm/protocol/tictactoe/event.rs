use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::parsed_message_type::ParsedMessageType;
use crate::didcomm::core::protocol;
use crate::didcomm::core::protocol::{Event, MessageDirection, Snafu};
use crate::didcomm::protocol::tictactoe::message::{Move, MoveMessage};
use crate::didcomm::protocol::tictactoe::TicTacToeDIDCommMessage;
use strum_macros::Display;

#[derive(Display, Debug, Clone, PartialEq, Eq)]
pub enum TicTacToeEvent {
    SendMove { to: String, moves: Vec<Move> },
    SendOutcome { to: String },
    ReceiveMove { from: String, moves: Vec<Move> },
    ReceiveOutcome { from: String },
}

impl Event for TicTacToeEvent {
    fn from_message(direction: MessageDirection, message: &Message) -> protocol::Result<Self> {
        let parsed_message_type =
            ParsedMessageType::from_message_type(&message.type_).map_err(|e| {
                Snafu {
                    details: format!("Invalid message type: {e}"),
                }
                .build()
            })?;

        let game_id = message.game_id();

        match (direction, parsed_message_type.message_type_name.as_str()) {
            (MessageDirection::Send, "move") => {
                let moves = message.payload::<MoveMessage>()?.moves;
                let to = message.recipient()?;

                Ok(Self::SendMove { to, moves })
            }
            (MessageDirection::Receive, "move") => {
                let moves = message.payload::<MoveMessage>()?.moves;
                let from = message.sender()?;

                Ok(Self::ReceiveMove { from, moves })
            }
            (MessageDirection::Receive, "outcome") => {
                let from = message.sender()?;

                Ok(Self::ReceiveOutcome { from })
            }
            (MessageDirection::Send, "outcome") => {
                let to = message.recipient()?;

                Ok(Self::SendOutcome { to })
            }
            (_, _) => protocol::Snafu {
                details: format!("Incorrect message type {}", message.type_),
            }
            .fail(),
        }
    }
}
