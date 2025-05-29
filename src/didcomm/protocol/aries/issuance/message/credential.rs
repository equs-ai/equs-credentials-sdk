use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use didcomm::AttachmentData;
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt};

use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::issuance::message::attachment_formats;
use crate::didcomm::protocol::aries::issuance::Result;
use crate::didcomm::protocol::aries::issuance::{
    InvalidAttachmentEncodingSnafu, InvalidAttachmentSnafu, InvalidCredentialRequestSnafu,
    ParseSnafu, ISSUE_CREDENTIAL, PROTOCOL_NAME, PROTOCOL_VERSION,
};
use crate::utils::http::MimeType;
use crate::vc::formats::json_ld_vc;
use crate::{impl_didcomm_message_conversion, threadlike};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Credential {
    #[serde(rename = "id")]
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: CredentialBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub please_ack: Option<Vec<String>>,
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Credential {
    pub fn create() -> Self {
        Credential::default()
    }

    pub fn set_comment(mut self, comment: Option<String>) -> Self {
        self.body.comment = comment;
        self
    }

    pub fn add_please_ack_id(mut self, id: String) -> Self {
        match &mut self.please_ack {
            Some(ref mut v) => v.push(id),
            None => self.please_ack = Some(vec![id]),
        }
        self
    }

    pub fn add_please_ack_id_to_current_message(self) -> Self {
        let id = self.id.to_string();
        self.add_please_ack_id(id)
    }

    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    pub fn set_ldp_vc_credential(self, credential: &json_ld_vc::VC) -> Result<Self> {
        let cred_json = serde_json::to_string(credential).context(ParseSnafu)?;
        let base64_data = BASE64_STANDARD.encode(cred_json);

        let attachment = Attachment::base64(base64_data)
            .id(MessageId::new().to_string())
            .media_type(MimeType::AppJson.as_str().to_string())
            .format(attachment_formats::LINKED_DATA_PROOF_VC_DETAIL.to_string())
            .finalize();

        Ok(self.add_attachment(attachment))
    }

    pub fn get_ldp_vc_credential(&self) -> Result<json_ld_vc::VC> {
        let attachment = self.attachments.first().ok_or_else(|| {
            InvalidCredentialRequestSnafu {
                details: "attachment not found",
            }
            .build()
        })?;

        ensure!(
            attachment.format.as_deref() == Some(attachment_formats::LINKED_DATA_PROOF_VC_DETAIL),
            InvalidAttachmentSnafu {
                details: format!("unsupported format: {:?}", attachment.format)
            }
        );

        let base64_str = if let AttachmentData::Base64 { value } = &attachment.data {
            &value.base64
        } else {
            return InvalidAttachmentEncodingSnafu {
                details: "only Base64 encoding is supported",
            }
            .fail();
        };

        let json_bytes = BASE64_STANDARD.decode(base64_str).map_err(|err| {
            InvalidAttachmentSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        serde_json::from_slice(&json_bytes).map_err(|err| {
            InvalidCredentialRequestSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

impl Default for Credential {
    fn default() -> Credential {
        Credential {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::Endpoint,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: ISSUE_CREDENTIAL.to_string(),
            },
            body: Default::default(),
            please_ack: Default::default(),
            attachments: vec![],
            thread: None,
        }
    }
}

impl_didcomm_message_conversion!(Credential);
threadlike!(Credential);

#[cfg(test)]
pub mod tests {
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use serde_json::json;

    use crate::didcomm::core::envelope::Attachment;
    use crate::didcomm::core::message_id::MessageId;
    use crate::didcomm::protocol::aries::common::message::thread::Thread;
    use crate::didcomm::protocol::aries::issuance::message::attachment_formats;
    use crate::didcomm::protocol::aries::issuance::message::credential::{
        Credential, CredentialBody,
    };
    use crate::utils::http::MimeType;

    #[test]
    fn test_credential_build_works() {
        let credential: Credential = Credential::create()
            .set_comment(_comment())
            .set_thread_id("testid")
            .add_attachment(_attachment());

        assert_eq!(_credential(), credential);
        let expected = r#"{"id":"testid","type":"https://didcomm.org/issue-credential/3.0/issue-credential","body":{"comment":"comment"},"attachments":[{"data":{"base64":"eyJzY2hlbWFfaWQiOiJOY1l4aURYa3BZaTZvdjVGY1lEaTFlOjI6Z3Z0OjEuMCIsImNyZWRfZGVmX2lkIjoiTmNZeGlEWGtwWWk2b3Y1RmNZRGkxZTozOkNMOk5jWXhpRFhrcFlpNm92NUZjWURpMWU6MjpndnQ6MS4wOlRBRzEiLCJ2YWx1ZXMiOnsiYXR0cmlidXRlIjp7InJhdyI6InZhbHVlIiwiZW5jb2RlZCI6IjExMzk0ODE3MTY0NTc0ODg2OTAxNzIyMTc5MTYyNzgxMDMzMzUifX19"},"id":"testid","media_type":"application/json","format":"hlindy/cred-abstract@v2.0"}],"thid":"testid"}"#;
        assert_eq!(expected, json!(credential).to_string());
    }

    fn _attachment() -> Attachment {
        Attachment::base64(
            BASE64_STANDARD.encode(json!({
                "schema_id":"NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0",
                "cred_def_id":"NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:TAG1",
                "values":{"attribute":{"raw":"value","encoded":"1139481716457488690172217916278103335"}}
            }).to_string())
        )
        .id(MessageId::new().to_string())
        .media_type(MimeType::AppJson.as_str().to_string())
        .format(attachment_formats::HYPERLEDGER_INDY_CREDENTIAL_ABSTRACT.to_string())
        .finalize()
    }

    fn _comment() -> Option<String> {
        Some(String::from("comment"))
    }

    pub fn _credential() -> Credential {
        Credential {
            id: MessageId::test_id(),
            body: CredentialBody {
                goal_code: None,
                replacement_id: None,
                comment: _comment(),
            },
            attachments: vec![_attachment()],
            thread: Some(Thread::new().set_thid(String::from("testid"))),
            ..Credential::default()
        }
    }
}
