use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::common::message::thread::Thread;
use crate::didcomm::protocol::aries::issuance::message::credential_preview::CredentialPreviewData;
use crate::didcomm::protocol::aries::issuance::{
    Error, InvalidAttachmentEncodingSnafu, InvalidAttributesStructureSnafu, ParseSnafu, Result,
    OFFER_CREDENTIAL, PROTOCOL_NAME, PROTOCOL_VERSION,
};
use crate::utils::http::MimeType;
use crate::vc::formats::json_ld_vc;
use crate::{impl_didcomm_message_conversion, impl_ldp_vc_details_format, threadlike, vc};
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use tracing::{debug, trace};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialOffer {
    #[serde(rename = "id")]
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: CredentialOfferBody,
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub thread: Option<Thread>,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialOfferBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default)]
    pub credential_preview: CredentialPreviewData,
}

impl CredentialOffer {
    pub fn create() -> Self {
        CredentialOffer::default()
    }

    pub fn set_id(mut self, id: String) -> Self {
        self.id = MessageId(id);
        self
    }

    pub fn set_comment(mut self, comment: Option<String>) -> Self {
        self.body.comment = comment;
        self
    }

    pub fn set_goal_code(mut self, goal_code: Option<String>) -> Self {
        self.body.goal_code = goal_code;
        self
    }

    pub fn set_replacement_id(mut self, replacement_id: Option<String>) -> Self {
        self.body.replacement_id = replacement_id;
        self
    }

    pub fn add_credential_preview_data(
        mut self,
        name: &str,
        value: &serde_json::Value,
        mime_type: MimeType,
    ) -> Result<CredentialOffer> {
        self.body.credential_preview = self
            .body
            .credential_preview
            .add_value(name, value, mime_type)?;
        Ok(self)
    }

    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    pub fn append_credential_preview(
        mut self,
        credential: &json_ld_vc::Credential,
    ) -> Result<CredentialOffer> {
        debug!(
            "Issuer::InitialState::append_credential_preview >>> cred_offer_msg: {:?}",
            self
        );

        let cred_sub = match credential {
            json_ld_vc::Credential::V1(crd) => crd.credential_subjects.clone(),
            json_ld_vc::Credential::V2(crd) => crd.credential_subjects.clone(),
        };

        for items in cred_sub {
            for item in items.claims() {
                let (key, value) = item;
                let value = value.clone().try_into().map_err(|err: vc::claims::Error| {
                    InvalidAttributesStructureSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;
                self = self.add_credential_preview_data(key, &value, MimeType::TextPlain)?;
            }
        }

        trace!("Issuer::InitialState::append_credential_preview <<<");
        Ok(self)
    }
}

impl Default for CredentialOffer {
    fn default() -> CredentialOffer {
        CredentialOffer {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::Endpoint,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: OFFER_CREDENTIAL.to_string(),
            },
            body: CredentialOfferBody::default(),
            attachments: vec![],
            thread: Default::default(),
        }
    }
}

impl TryFrom<CredentialOffer> for Attachment {
    type Error = Error;

    fn try_from(value: CredentialOffer) -> Result<Self> {
        let json = serde_json::to_value(&value).context(ParseSnafu)?;

        Ok(Attachment::json(json)
            .id(MessageId::new().to_string())
            .media_type(MimeType::AppJson.as_str().to_string())
            .finalize())
    }
}

impl TryFrom<Attachment> for CredentialOffer {
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

impl_ldp_vc_details_format!(CredentialOffer);
impl_didcomm_message_conversion!(CredentialOffer);
threadlike!(CredentialOffer);

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::didcomm::protocol::aries::issuance::message::attachment_formats;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use serde_json::json;

    #[test]
    fn test_credential_offer_build_works() {
        let credential_offer: CredentialOffer = CredentialOffer::create()
            .set_comment(_comment())
            .add_attachment(_attachment())
            .add_credential_preview_data(
                "attribute",
                &serde_json::Value::String("value".to_string()),
                MimeType::TextPlain,
            )
            .unwrap();

        assert_eq!(_credential_offer(), credential_offer);
        let expected = r#"{"id":"testid","type":"https://didcomm.org/issue-credential/3.0/offer-credential","body":{"comment":"comment","credential_preview":{"id":"testid","type":"did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/3.0/credential-preview","body":{"attributes":[{"name":"attribute","value":"value"}]}}},"attachments":[{"data":{"base64":"eyJzY2hlbWFfaWQiOiJOY1l4aURYa3BZaTZvdjVGY1lEaTFlOjI6Z3Z0OjEuMCIsImNyZWRfZGVmX2lkIjoiTmNZeGlEWGtwWWk2b3Y1RmNZRGkxZTozOkNMOk5jWXhpRFhrcFlpNm92NUZjWURpMWU6MjpndnQ6MS4wOlRBRzEifQ=="},"id":"testid","media_type":"application/json","format":"hlindy/cred-abstract@v2.0"}]}"#;
        assert_eq!(expected, json!(credential_offer).to_string());
    }

    fn _attachment() -> Attachment {
        Attachment::base64(
            BASE64_STANDARD.encode(json!({
                "schema_id":"NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0",
                "cred_def_id":"NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:TAG1"
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

    pub fn _value() -> (&'static str, &'static str) {
        ("attribute", "value")
    }

    pub fn _preview_data() -> CredentialPreviewData {
        let (name, value) = _value();
        CredentialPreviewData::new()
            .add_value(name, &json!(value), MimeType::TextPlain)
            .unwrap()
    }

    pub fn _credential_offer() -> CredentialOffer {
        CredentialOffer {
            body: CredentialOfferBody {
                comment: _comment(),
                credential_preview: _preview_data(),
                ..CredentialOfferBody::default()
            },
            attachments: vec![_attachment()],
            ..CredentialOffer::default()
        }
    }
}
