pub mod presentation;
pub mod presentation_request;
pub mod proof_request;

use crate::didcomm::connection::ConnectionRecord;
use crate::didcomm::core::envelope::Message;
use crate::didcomm::core::message_type::parse_message_type;
use crate::didcomm::core::protocol;
use crate::didcomm::protocol::aries::present_proof::message::presentation::Presentation;
use crate::didcomm::protocol::aries::present_proof::message::presentation_request::PresentationRequest;
use crate::didcomm::protocol::aries::present_proof::{PRESENTATION, REQUEST_PRESENTATION};
use crate::didcomm::protocol::aries::problem_report::PROBLEM_REPORT;
use crate::didcomm::protocol::aries::problem_report::message::ProblemReport;
use proof_request::ProofRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum HolderMessages {
    PresentationRequestReceived(PresentationRequest),
    RejectPresentationRequest(String),
    PreparePresentation,
    SetPresentation(Presentation),
    SendPresentation,
    PresentationRejectReceived(ProblemReport),
    ProblemReport(ProblemReport),
}

impl HolderMessages {
    pub fn get_state(&self) -> String {
        match &self {
            Self::PresentationRequestReceived(_) => "PresentationRequestReceived".to_string(),
            Self::RejectPresentationRequest(_) => "RejectPresentationRequest".to_string(),
            Self::PreparePresentation => "PreparePresentation".to_string(),
            Self::SetPresentation(_) => "SetPresentation".to_string(),
            Self::SendPresentation => "SendPresentation".to_string(),
            Self::PresentationRejectReceived(_) => "PresentationRejectReceived".to_string(),
            Self::ProblemReport(_) => "ProblemReport".to_string(),
        }
    }
}

impl TryFrom<Message> for HolderMessages {
    type Error = protocol::Error;

    fn try_from(value: Message) -> protocol::Result<Self> {
        let (_, _, _, type_) = parse_message_type(&value.type_).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        match type_.as_str() {
            REQUEST_PRESENTATION => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(HolderMessages::PresentationRequestReceived),
            PROBLEM_REPORT => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(HolderMessages::ProblemReport),
            type_ => protocol::Snafu {
                details: format!("Unsupported message type: {type_}"),
            }
            .fail(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum VerifierMessages {
    SendPresentationRequest(ConnectionRecord),
    PresentationReceived(Presentation),
    PresentationRejectReceived(ProblemReport),
    RequestPresentation(ProofRequest),
    ProblemReport(ProblemReport),
    Unknown,
}

impl TryFrom<Message> for VerifierMessages {
    type Error = protocol::Error;

    fn try_from(value: Message) -> protocol::Result<Self> {
        let (_, _, _, type_) = parse_message_type(&value.type_).map_err(|err| {
            protocol::Snafu {
                details: err.to_string(),
            }
            .build()
        })?;

        match type_.as_str() {
            PRESENTATION => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(VerifierMessages::PresentationReceived),
            PROBLEM_REPORT => value
                .try_into()
                .map_err(|err: serde_json::Error| {
                    protocol::Snafu {
                        details: err.to_string(),
                    }
                    .build()
                })
                .map(VerifierMessages::ProblemReport),
            type_ => protocol::Snafu {
                details: format!("Unsupported message type: {type_}"),
            }
            .fail(),
        }
    }
}
