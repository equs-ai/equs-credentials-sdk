use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::core::message_type::{MessageType, MessageTypePrefix};
use crate::didcomm::protocol::aries::issuance::{CREDENTIAL_PREVIEW, Result};
use crate::didcomm::protocol::aries::issuance::{
    InvalidCredentialValueTypeSnafu, PROTOCOL_NAME, PROTOCOL_VERSION,
};
use crate::utils::http::MimeType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialPreviewData {
    #[serde(rename = "id")]
    pub id: MessageId,
    #[serde(rename = "type")]
    pub type_: MessageType,
    pub body: CredentialPreviewBody,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialPreviewBody {
    pub attributes: Vec<CredentialValue>,
}

impl CredentialPreviewData {
    pub fn new() -> Self {
        CredentialPreviewData::default()
    }

    pub fn add_value(
        mut self,
        name: &str,
        value: &serde_json::Value,
        mime_type: MimeType,
    ) -> Result<CredentialPreviewData> {
        let data_value = match mime_type {
            MimeType::TextPlain => CredentialValue {
                name: name.to_string(),
                value: value.clone(),
                media_type: None,
            },
            _ => return InvalidCredentialValueTypeSnafu { type_: mime_type }.fail(),
        };
        self.body.attributes.push(data_value);
        Ok(self)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default)]
pub struct CredentialValue {
    pub name: String,
    pub value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<MimeType>,
}

impl Default for CredentialPreviewData {
    fn default() -> CredentialPreviewData {
        CredentialPreviewData {
            id: MessageId::default(),
            type_: MessageType {
                prefix: MessageTypePrefix::DID,
                family: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION.to_string(),
                type_: CREDENTIAL_PREVIEW.to_string(),
            },
            body: CredentialPreviewBody { attributes: vec![] },
        }
    }
}
