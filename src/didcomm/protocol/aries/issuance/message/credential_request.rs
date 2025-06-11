use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::issuance::{
    PROTOCOL_NAME, PROTOCOL_VERSION, REQUEST_CREDENTIAL,
};
use crate::{impl_didcomm_message_conversion, impl_ldp_vc_details_format, threadlike};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialRequest {
    #[serde(rename = "id")]
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: CredentialRequestBody,
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl CredentialRequest {
    pub fn create() -> Self {
        CredentialRequest::default()
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
}

impl Default for CredentialRequest {
    fn default() -> CredentialRequest {
        CredentialRequest {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::Endpoint,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: REQUEST_CREDENTIAL.to_string(),
            },
            attachments: vec![],
            body: Default::default(),
            thread: None,
        }
    }
}

impl_ldp_vc_details_format!(CredentialRequest);
impl_didcomm_message_conversion!(CredentialRequest);
threadlike!(CredentialRequest);

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::didcomm::core::envelope::Attachment;
    use crate::didcomm::protocol::aries::issuance::message::attachment_formats;
    use crate::utils::http::MimeType;
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use serde_json::json;

    #[test]
    fn test_credential_request_build_works() {
        let credential_request: CredentialRequest = CredentialRequest::create()
            .set_comment(_comment())
            .add_attachment(_attachment());

        assert_eq!(_credential_request(), credential_request);
        let expected = r#"{"id":"testid","type":"https://didcomm.org/issue-credential/3.0/request-credential","body":{"comment":"comment"},"attachments":[{"data":{"base64":"eyJwcm92ZXJfZGlkIjoiVnNLVjdnclIxQlVFMjltRzJGbTJrWCIsImNyZWRfZGVmX2lkIjoiTmNZeGlEWGtwWWk2b3Y1RmNZRGkxZTozOkNMOk5jWXhpRFhrcFlpNm92NUZjWURpMWU6MjpndnQ6MS4wOlRBRzEifQ=="},"id":"testid","media_type":"application/json","format":"hlindy/cred-req@v2.0"}]}"#;
        assert_eq!(expected, json!(credential_request).to_string());
    }

    fn _attachment() -> Attachment {
        Attachment::base64(
            BASE64_STANDARD.encode(json!({
                "prover_did":"VsKV7grR1BUE29mG2Fm2kX",
                "cred_def_id":"NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:TAG1"
            }).to_string())
        )
        .id(MessageId::new().to_string())
        .media_type(MimeType::AppJson.as_str().to_string())
        .format(attachment_formats::HYPERLEDGER_INDY_CREDENTIAL_REQUEST.to_string())
        .finalize()
    }

    fn _comment() -> String {
        String::from("comment")
    }

    pub fn _credential_request() -> CredentialRequest {
        CredentialRequest {
            id: MessageId::default(),
            body: CredentialRequestBody {
                goal_code: None,
                comment: Some(_comment()),
            },
            attachments: vec![_attachment()],
            ..CredentialRequest::default()
        }
    }
}
