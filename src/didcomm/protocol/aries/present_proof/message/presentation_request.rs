use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::present_proof::{
    Error, InvalidAttachmentEncodingSnafu, PROTOCOL_NAME, PROTOCOL_VERSION, ParseSnafu,
    REQUEST_PRESENTATION, Result,
};
use crate::impl_didcomm_message_conversion;
use crate::utils::http::MimeType;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PresentationRequest {
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: PresentationRequestBody,
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct PresentationRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default)]
    pub will_confirm: bool,
}

impl PresentationRequest {
    pub fn new() -> Self {
        PresentationRequest::default()
    }

    pub fn set_comment(mut self, comment: String) -> Self {
        self.body.comment = Some(comment);
        self
    }

    pub fn set_goal_code(mut self, goal_code: String) -> Self {
        self.body.goal_code = Some(goal_code);
        self
    }

    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    pub fn set_thread_id(mut self, id: &str) -> Self {
        self.thread = Some(Thread::new().set_thid(id.to_string()));
        self
    }
}

impl Default for PresentationRequest {
    fn default() -> Self {
        Self {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::Endpoint,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: REQUEST_PRESENTATION.to_string(),
            },
            body: PresentationRequestBody::default(),
            attachments: vec![],
            thread: None,
        }
    }
}

impl TryFrom<Attachment> for PresentationRequest {
    type Error = Error;

    fn try_from(value: Attachment) -> Result<Self> {
        let json = if let didcomm::AttachmentData::Json { value } = value.data {
            value.json
        } else {
            return InvalidAttachmentEncodingSnafu {
                details: "The credential offer message must be attached in JSON format",
            }
            .fail();
        };

        serde_json::from_value(json).context(ParseSnafu)
    }
}
impl TryFrom<PresentationRequest> for Attachment {
    type Error = Error;

    fn try_from(value: PresentationRequest) -> Result<Self> {
        let json = serde_json::to_value(&value).context(ParseSnafu)?;

        Ok(Attachment::json(json)
            .id(MessageId::new().to_string())
            .media_type(MimeType::AppJson.as_str().to_string())
            .finalize())
    }
}

impl_didcomm_message_conversion!(PresentationRequest);

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::json;

    fn _attachment() -> serde_json::Value {
        json!([{"name": "John"}])
    }

    fn _comment() -> String {
        String::from("comment")
    }

    pub fn thread_id() -> String {
        _presentation_request().id.0
    }

    pub fn thread() -> Thread {
        Thread::new().set_thid(_presentation_request().id.0)
    }

    pub fn _presentation_request() -> PresentationRequest {
        let attachment = Attachment::json(_attachment()).finalize();

        PresentationRequest {
            id: MessageId::test_id(),
            body: PresentationRequestBody {
                comment: Some(_comment()),
                ..PresentationRequestBody::default()
            },
            attachments: vec![attachment],
            ..PresentationRequest::default()
        }
    }

    #[test]
    fn test_presentation_request_build_works() {
        let presentation_request: PresentationRequest = PresentationRequest::default()
            .set_comment(_comment())
            .add_attachment(Attachment::json(json!([{"name": "John"}])).finalize());

        assert_eq!(_presentation_request(), presentation_request);
        let expected = r#"{"id":"testid","type":"https://didcomm.org/present-proof/3.0/request-presentation","body":{"comment":"comment","will_confirm":false},"attachments":[{"data":{"json":[{"name":"John"}]}}]}"#;
        assert_eq!(expected, json!(presentation_request).to_string());
    }
}
