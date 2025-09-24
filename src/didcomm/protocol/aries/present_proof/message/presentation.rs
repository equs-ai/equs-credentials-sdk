use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::present_proof::{
    PRESENTATION, PROTOCOL_NAME, PROTOCOL_VERSION,
};
use crate::impl_didcomm_message_conversion;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Presentation {
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: PresentationBody,
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PresentationBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Presentation {
    pub fn create() -> Self {
        Presentation::default()
    }

    pub fn set_comment(mut self, comment: Option<String>) -> Self {
        self.body.comment = comment;
        self
    }

    pub fn set_goal_code(mut self, goal_code: Option<String>) -> Self {
        self.body.goal_code = goal_code;
        self
    }

    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }
    pub fn add_attachments(mut self, attachments: Vec<Attachment>) -> Self {
        for attachment in attachments {
            self.attachments.push(attachment);
        }
        self
    }

    pub fn set_thread_id(mut self, id: &str) -> Self {
        self.thread = Some(Thread::new().set_thid(id.to_string()));
        self
    }
}
impl Default for Presentation {
    fn default() -> Presentation {
        Presentation {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::Endpoint,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: PRESENTATION.to_string(),
            },
            body: PresentationBody::default(),
            attachments: vec![],
            thread: Default::default(),
        }
    }
}

impl_didcomm_message_conversion!(Presentation);
