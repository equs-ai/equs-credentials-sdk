use serde::{Deserialize, Serialize};

use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::issuance::message::credential_preview::CredentialPreviewData;
use crate::didcomm::protocol::aries::issuance::{
    PROPOSE_CREDENTIAL, PROTOCOL_NAME, PROTOCOL_VERSION,
};
use crate::{impl_didcomm_message_conversion, impl_ldp_vc_details_format, threadlike};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialProposal {
    #[serde(rename = "id")]
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: CredentialProposalBody,
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialProposalBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_preview: Option<CredentialPreviewData>,
}

impl CredentialProposal {
    pub fn create() -> Self {
        CredentialProposal::default()
    }

    pub fn set_comment(mut self, comment: Option<String>) -> Self {
        self.body.comment = comment;
        self
    }

    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }
}

impl Default for CredentialProposal {
    fn default() -> CredentialProposal {
        CredentialProposal {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::Endpoint,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: PROPOSE_CREDENTIAL.to_string(),
            },
            body: Default::default(),
            attachments: vec![],
            thread: Default::default(),
        }
    }
}

impl_ldp_vc_details_format!(CredentialProposal);
impl_didcomm_message_conversion!(CredentialProposal);
threadlike!(CredentialProposal);

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::didcomm::protocol::aries::issuance::message::credential_offer::tests::_value;
    use crate::utils::http::MimeType;
    use serde_json::json;

    #[test]
    fn test_credential_proposal_build_works() {
        let credential_proposal: CredentialProposal = CredentialProposal::create()
            .set_comment(_comment())
            .set_thread_id("testid");

        assert_eq!(_credential_proposal(), credential_proposal);
        let expected = r#"{"id":"testid","type":"https://didcomm.org/issue-credential/3.0/propose-credential","body":{"comment":"comment"},"attachments":[],"thid":"testid"}"#;
        assert_eq!(expected, json!(credential_proposal).to_string());
    }

    pub fn _credential_proposal() -> CredentialProposal {
        CredentialProposal {
            id: MessageId::default(),
            body: CredentialProposalBody {
                goal_code: None,
                comment: _comment(),
                credential_preview: None,
            },
            thread: Some(Thread::new().set_thid(String::from("testid"))),
            ..CredentialProposal::default()
        }
    }

    fn _comment() -> Option<String> {
        Some(String::from("comment"))
    }

    fn _schema_id() -> String {
        String::from("schema:id")
    }

    fn _cred_def_id() -> String {
        String::from("cred_def_id:id")
    }

    fn _credential_preview_data() -> CredentialPreviewData {
        let (name, value) = _value();

        CredentialPreviewData::new()
            .add_value(name, &json!(value), MimeType::TextPlain)
            .unwrap()
    }
}
