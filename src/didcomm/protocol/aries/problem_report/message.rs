use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::common::message::status::Status;
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::problem_report::{
    PROBLEM_REPORT, PROTOCOL_NAME, PROTOCOL_VERSION,
};
use crate::{impl_didcomm_message_conversion, threadlike};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProblemReport {
    #[serde(rename = "id")]
    id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: ProblemReportBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack: Option<Vec<String>>,
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProblemReportBody {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_to: Option<String>,
}

impl ProblemReport {
    pub fn create() -> Self {
        ProblemReport::default()
    }

    pub fn set_message_type(mut self, type_: &MessageType) -> Self {
        self.type_ = MessageType {
            prefix: type_.prefix.clone(),
            family: type_.family.clone(),
            version: type_.version.clone(),
            type_: self.type_.type_.clone(),
        };
        self
    }

    pub fn set_code(mut self, code: ProblemReportCode) -> Self {
        self.body.code = code.code();
        self
    }

    pub fn set_comment(mut self, comment: String) -> Self {
        self.body.comment = Some(comment);
        self
    }

    pub fn add_arg(mut self, arg: String) -> Self {
        match &mut self.body.args {
            Some(v) => v.push(arg),
            None => self.body.args = Some(vec![arg]),
        }
        self
    }

    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }
}

impl Default for ProblemReport {
    fn default() -> ProblemReport {
        ProblemReport {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::DID,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: PROBLEM_REPORT.to_string(),
            },
            body: Default::default(),
            ack: None,
            attachments: vec![],
            thread: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProblemReportCode {
    Unimplemented,
    InvalidCredentialOffer,
    InvalidCredentialRequest,
    InvalidCredential,
    CredentialRejected,
    InvalidPresentationRequest,
    InvalidPresentation,
    PresentationRejected,
    Other(String),
}

impl ProblemReportCode {
    pub fn code(&self) -> String {
        match self {
            ProblemReportCode::Unimplemented => "e.m.me.unimplemented".to_string(),
            ProblemReportCode::InvalidCredentialOffer => {
                "e.m.msg.invalid-credential-offer".to_string()
            }
            ProblemReportCode::InvalidCredentialRequest => {
                "e.m.msg.invalid-credential-request".to_string()
            }
            ProblemReportCode::InvalidCredential => "e.m.msg.invalid-credential".to_string(),
            ProblemReportCode::CredentialRejected => "e.p.msg.rejection".to_string(),
            ProblemReportCode::InvalidPresentationRequest => "e.m.msg.invalid-request".to_string(),
            ProblemReportCode::InvalidPresentation => "e.m.msg.invalid-presentation".to_string(),
            ProblemReportCode::PresentationRejected => "e.p.msg.rejection".to_string(),
            ProblemReportCode::Other(error) => error.to_string(),
        }
    }
}

pub enum Reason {
    Fail,
    Reject,
}

impl Reason {
    pub fn to_status(&self, problem_report: ProblemReport) -> Status {
        match self {
            Reason::Fail => Status::Failed(problem_report),
            Reason::Reject => Status::Rejected(Some(problem_report)),
        }
    }
}

impl_didcomm_message_conversion!(ProblemReport);
threadlike!(ProblemReport);
