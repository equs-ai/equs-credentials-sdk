pub mod credential;
pub mod credential_offer;
pub mod credential_preview;
pub mod credential_proposal;
pub mod credential_request;

pub mod attachment_formats {
    pub const DIF_CREDENTIAL_MANIFEST: &str = "dif/credential-manifest@v1.0";
    pub const LINKED_DATA_PROOF_VC_DETAIL: &str = "aries/ld-proof-vc-detail@v1.0";
    pub const HYPERLEDGER_INDY_CREDENTIAL_FILTER: &str = "hlindy/cred-filter@v2.0";
    pub const HYPERLEDGER_INDY_CREDENTIAL_ABSTRACT: &str = "hlindy/cred-abstract@v2.0";
    pub const HYPERLEDGER_INDY_CREDENTIAL_REQUEST: &str = "hlindy/cred-req@v2.0";
}

#[macro_export]
macro_rules! impl_ldp_vc_details_format (($type:ident) => (
    impl $type {
        pub fn set_ldp_vc_credential(self, credential: &$crate::vc::formats::json_ld_vc::Credential) -> $crate::didcomm::protocol::aries::issuance::Result<Self> {
            use snafu::ResultExt as _;
            use base64::Engine as _;

            let cred_json = ::serde_json::to_string(credential).context($crate::didcomm::protocol::aries::issuance::ParseSnafu)?;

            let base64_data = ::base64::prelude::BASE64_STANDARD.encode(cred_json);

            let attachment = $crate::didcomm::core::envelope::Attachment::base64(base64_data)
                .id($crate::didcomm::core::message_id::MessageId::new().to_string())
                .media_type($crate::utils::http::MimeType::AppJson.as_str().to_string())
                .format($crate::didcomm::protocol::aries::issuance::message::attachment_formats::LINKED_DATA_PROOF_VC_DETAIL.to_string())
                .finalize();

            Ok(self.add_attachment(attachment))
        }

        pub fn get_ldp_vc_credential(&self) -> $crate::didcomm::protocol::aries::issuance::Result<$crate::vc::formats::json_ld_vc::Credential> {
            use base64::Engine as _;

            let attachment = self.attachments.first().ok_or_else(|| {
                $crate::didcomm::protocol::aries::issuance::InvalidCredentialRequestSnafu {
                    details: "attachment not found",
                }
                .build()
            })?;

            snafu::ensure!(
                attachment.format.as_deref() == Some($crate::didcomm::protocol::aries::issuance::message::attachment_formats::LINKED_DATA_PROOF_VC_DETAIL),
                $crate::didcomm::protocol::aries::issuance::InvalidAttachmentSnafu {
                    details: format!("unsupported format: {:?}", attachment.format)
                }
            );

            let base64_str = if let ::didcomm::AttachmentData::Base64 { value } = &attachment.data {
                &value.base64
            } else {
                return $crate::didcomm::protocol::aries::issuance::InvalidAttachmentEncodingSnafu {
                    details: "only Base64 encoding is supported",
                }
                .fail();
            };

            let json_bytes = ::base64::prelude::BASE64_STANDARD.decode(base64_str).map_err(|err| {
                $crate::didcomm::protocol::aries::issuance::InvalidAttachmentSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

            let unsigned_credential = serde_json::from_slice(&json_bytes).map_err(|err| {
                $crate::didcomm::protocol::aries::issuance::InvalidCredentialRequestSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

            Ok(unsigned_credential)
        }
    }
));
