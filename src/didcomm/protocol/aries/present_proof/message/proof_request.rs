use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::protocol::aries::present_proof::{Error, ParseSnafu, Result};
use crate::impl_didcomm_message_conversion;
use crate::utils::http::MimeType;
use openid4vp::core::presentation_definition::PresentationDefinition;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProofRequest {
    pub input: PresentationDefinition,
}
impl ProofRequest {
    pub fn new(input: PresentationDefinition) -> Self {
        Self { input }
    }
}

impl TryFrom<ProofRequest> for Attachment {
    type Error = Error;

    fn try_from(value: ProofRequest) -> Result<Self> {
        let json = serde_json::to_value(&value.input).context(ParseSnafu)?;

        Ok(Attachment::json(json)
            .id(MessageId::new().to_string())
            .media_type(MimeType::AppJson.as_str().to_string())
            .finalize())
    }
}

impl_didcomm_message_conversion!(ProofRequest);
