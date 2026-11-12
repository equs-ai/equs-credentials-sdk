//! The proof request a verifier sends: what to present, and how to bind the answer.

use crate::didcomm::core::envelope::Attachment;
use crate::didcomm::core::message_id::MessageId;
use crate::didcomm::protocol::aries::present_proof::{
    DecodeSnafu, Error, InvalidAttachmentEncodingSnafu, ParseSnafu, Result,
};
use crate::impl_didcomm_message_conversion;
use crate::utils::http::MimeType;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use didcomm::AttachmentData;
use openid4vp::core::presentation_definition::PresentationDefinition;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;

/// Attachment format of a presentation-definition request (Aries RFC 0510).
pub const DIF_PRESENTATION_EXCHANGE_DEFINITIONS: &str =
    "dif/presentation-exchange/definitions@v1.0";

/// Values the presentation's proof must include. Both are optional.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ProofOptions {
    /// Random value that keeps the proof from being replayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    /// Who the proof is meant for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProofRequest {
    pub input: PresentationDefinition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<ProofOptions>,
}

/// The attachment body: wrapped with options (RFC 0510), or a bare definition from older
/// verifiers.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum ProofRequestBody {
    Wrapped {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        options: Option<ProofOptions>,
        presentation_definition: PresentationDefinition,
    },
    Bare(PresentationDefinition),
}

impl ProofRequest {
    pub fn new(input: PresentationDefinition) -> Self {
        Self {
            input,
            options: None,
        }
    }

    pub fn set_options(mut self, options: ProofOptions) -> Self {
        self.options = Some(options);
        self
    }

    /// Builds the request attachment. Without options it holds a bare definition, which older
    /// holders can read.
    pub(crate) fn to_attachment(&self, id: String) -> Result<Attachment> {
        let body = match &self.options {
            Some(options) => ProofRequestBody::Wrapped {
                options: Some(options.to_owned()),
                presentation_definition: self.input.to_owned(),
            },
            None => ProofRequestBody::Bare(self.input.to_owned()),
        };
        let json = serde_json::to_value(&body).context(ParseSnafu)?;

        Ok(Attachment::json(json)
            .id(id)
            .media_type(MimeType::AppJson.as_str().to_string())
            .format(DIF_PRESENTATION_EXCHANGE_DEFINITIONS.to_string())
            .finalize())
    }
}

impl TryFrom<ProofRequest> for Attachment {
    type Error = Error;

    fn try_from(value: ProofRequest) -> Result<Self> {
        value.to_attachment(MessageId::new().to_string())
    }
}

impl TryFrom<&Attachment> for ProofRequest {
    type Error = Error;

    /// Reads a request attachment, labelled with its format or not.
    ///
    /// # Errors
    ///
    /// * [Error::InvalidAttachmentEncoding] - another format, or a link attachment.
    /// * [Error::Decode] / [Error::Parse] - the body is not a proof request.
    fn try_from(attachment: &Attachment) -> Result<Self> {
        if let Some(format) = &attachment.format
            && format != DIF_PRESENTATION_EXCHANGE_DEFINITIONS
        {
            return InvalidAttachmentEncodingSnafu {
                details: "unsupported presentation request attachment format",
            }
            .fail();
        }

        let body: ProofRequestBody = match &attachment.data {
            AttachmentData::Json { value } => {
                serde_json::from_value(value.json.to_owned()).context(ParseSnafu)?
            }
            AttachmentData::Base64 { value } => {
                let json = BASE64_STANDARD.decode(&value.base64).context(DecodeSnafu)?;
                serde_json::from_slice(&json).context(ParseSnafu)?
            }
            AttachmentData::Links { .. } => {
                return InvalidAttachmentEncodingSnafu { details: "Links" }.fail();
            }
        };

        Ok(match body {
            ProofRequestBody::Wrapped {
                options,
                presentation_definition,
            } => ProofRequest {
                input: presentation_definition,
                options,
            },
            ProofRequestBody::Bare(presentation_definition) => {
                ProofRequest::new(presentation_definition)
            }
        })
    }
}

impl_didcomm_message_conversion!(ProofRequest);

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn proof_request_round_trips_through_an_attachment_with_its_options() {
        let options = ProofOptions {
            challenge: Some("challenge".to_owned()),
            domain: Some("did:example:verifier".to_owned()),
        };
        let request = ProofRequest::new(definition()).set_options(options.to_owned());

        let attachment: Attachment = request.try_into().unwrap();
        let parsed = ProofRequest::try_from(&attachment).unwrap();

        assert_eq!(
            attachment.format.as_deref(),
            Some(DIF_PRESENTATION_EXCHANGE_DEFINITIONS)
        );
        assert_eq!(parsed.options, Some(options));
        assert_eq!(parsed.input.id(), definition().id());
    }

    #[rstest]
    #[case::bare_definition(definition_json(), None)]
    #[case::wrapped_without_options(json!({ "presentation_definition": definition_json() }), None)]
    #[case::challenge_only(
        json!({ "options": { "challenge": "c" }, "presentation_definition": definition_json() }),
        Some(ProofOptions { challenge: Some("c".to_owned()), domain: None })
    )]
    #[case::domain_only(
        json!({ "options": { "domain": "us.gov/DriversLicense" }, "presentation_definition": definition_json() }),
        Some(ProofOptions { challenge: None, domain: Some("us.gov/DriversLicense".to_owned()) })
    )]
    fn proof_request_reads_every_rfc_0510_body(
        #[case] body: Value,
        #[case] expected_options: Option<ProofOptions>,
    ) {
        let attachment = Attachment::json(body)
            .format(DIF_PRESENTATION_EXCHANGE_DEFINITIONS.to_string())
            .finalize();

        let parsed = ProofRequest::try_from(&attachment).unwrap();

        assert_eq!(parsed.options, expected_options);
        assert_eq!(parsed.input.id(), definition().id());
    }

    #[test]
    fn proof_request_reads_an_attachment_without_a_format() {
        let attachment = Attachment::json(definition_json()).finalize();

        let parsed = ProofRequest::try_from(&attachment).unwrap();

        assert_eq!(parsed.input.id(), definition().id());
    }

    #[test]
    fn proof_request_rejects_another_attachment_format() {
        let attachment = Attachment::json(definition_json())
            .format("hlindy/proof-req@v2.0".to_string())
            .finalize();

        let result = ProofRequest::try_from(&attachment);

        assert!(
            matches!(result, Err(Error::InvalidAttachmentEncoding { .. })),
            "{result:?}"
        );
    }

    fn definition() -> PresentationDefinition {
        serde_json::from_value(definition_json()).unwrap()
    }

    fn definition_json() -> Value {
        json!({ "id": "pd", "input_descriptors": [] })
    }
}
