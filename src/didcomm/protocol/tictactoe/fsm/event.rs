use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::core::protocol::{Error, Result, Snafu};
use crate::didcomm::core::{message_type, protocol};
use crate::didcomm::protocol::tictactoe::message::{MoveMessageBody, OutcomeMessageBody};
use crate::didcomm::protocol::tictactoe::{
    MOVE_MESSAGE_TYPE, OUTCOME_MESSAGE_TYPE, PROTOCOL_NAME, PROTOCOL_VERSION,
    TicTacToeDIDCommMessage,
};
use serde::Serialize;
use strum_macros::Display;
use uuid::Uuid;

#[derive(Display, Debug, Clone, PartialEq, Eq)]
pub enum TicTacToeEvent {
    SendMove {
        game_id: String,
        from: String,
        to: String,
        move_: MoveMessageBody,
    },
    SendOutcome {
        game_id: String,
        from: String,
        to: String,
        outcome: OutcomeMessageBody,
    },
    ReceiveMove {
        game_id: String,
        from: String,
        to: String,
        move_: MoveMessageBody,
    },
    ReceiveOutcome {
        game_id: String,
        from: String,
        to: String,
        outcome: OutcomeMessageBody,
    },
}

impl TicTacToeEvent {
    pub fn game_id(&self) -> &str {
        match self {
            TicTacToeEvent::SendMove { game_id, .. } => game_id,
            TicTacToeEvent::SendOutcome { game_id, .. } => game_id,
            TicTacToeEvent::ReceiveMove { game_id, .. } => game_id,
            TicTacToeEvent::ReceiveOutcome { game_id, .. } => game_id,
        }
    }
}

impl TryInto<Option<Message>> for TicTacToeEvent {
    type Error = Error;

    fn try_into(self) -> Result<Option<Message>> {
        match self {
            TicTacToeEvent::SendMove {
                game_id,
                from,
                to,
                move_,
            } => build_message(game_id, from, to, MOVE_MESSAGE_TYPE.to_string(), move_).map(Some),
            TicTacToeEvent::SendOutcome {
                game_id,
                from,
                to,
                outcome,
            } => build_message(game_id, from, to, OUTCOME_MESSAGE_TYPE.to_string(), outcome)
                .map(Some),
            _ => Ok(None),
        }
    }
}

impl TryFrom<Message> for TicTacToeEvent {
    type Error = Error;

    fn try_from(message: Message) -> Result<Self> {
        let (_, _, _, type_) = message_type::parse_message_type(&message.type_).map_err(|e| {
            Snafu {
                details: format!("Invalid message type: {e}"),
            }
            .build()
        })?;

        let game_id = message.game_id();

        match type_.as_str() {
            MOVE_MESSAGE_TYPE => {
                let game_id = message.game_id()?.to_string();
                let move_ = message.payload::<MoveMessageBody>()?;
                let from = message.sender()?;
                let to: String = message.recipient()?;

                Ok(Self::ReceiveMove {
                    game_id,
                    from,
                    to,
                    move_,
                })
            }
            OUTCOME_MESSAGE_TYPE => {
                let game_id = message.game_id()?.to_string();
                let outcome = message.payload::<OutcomeMessageBody>()?;
                let from = message.sender()?;
                let to: String = message.recipient()?;

                Ok(Self::ReceiveOutcome {
                    game_id,
                    from,
                    to,
                    outcome,
                })
            }
            _ => protocol::Snafu {
                details: format!("Incorrect message type {}", message.type_),
            }
            .fail(),
        }
    }
}

fn build_message<T: Serialize>(
    game_id: String,
    from: String,
    to: String,
    type_: String,
    body: T,
) -> Result<Message> {
    let message_type = MessageType {
        prefix: MessageTypePrefix::Endpoint,
        family: PROTOCOL_NAME.to_string(),
        version: PROTOCOL_VERSION.to_string(),
        type_,
    };

    let message = Message::build(
        Uuid::new_v4().to_string(),
        message_type.to_string(),
        serde_json::to_value(&body).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?,
    )
    .thid(game_id.to_owned())
    .from(from)
    .to(to)
    .finalize();

    Ok(message)
}
