use serde::{Deserialize, Serialize};

use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::empty::{EMPTY, PROTOCOL_NAME, PROTOCOL_VERSION};
use crate::{impl_didcomm_message_conversion, threadlike};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Empty {
    #[serde(rename = "id")]
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub ack: Option<Vec<String>>,
    pub body: (),
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}

impl Empty {
    pub fn create() -> Empty {
        Empty::default()
    }

    pub fn add_ack_id(mut self, id: String) -> Self {
        match &mut self.ack {
            Some(v) => v.push(id),
            None => self.ack = Some(vec![id]),
        }
        self
    }

    pub fn add_ack_ids(mut self, mut ids: Vec<String>) -> Self {
        match &mut self.ack {
            Some(v) => v.append(&mut ids),
            None => self.ack = Some(ids),
        }
        self
    }

    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }
}

impl Default for Empty {
    fn default() -> Empty {
        Empty {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::DID,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: EMPTY.to_string(),
            },
            ack: None,
            body: (),
            attachments: vec![],
            thread: None,
        }
    }
}

threadlike!(Empty);
impl_didcomm_message_conversion!(Empty);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PleaseAck {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on: Option<Vec<String>>,
}
