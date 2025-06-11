use crate::kms;
use crate::vc::StatusList;
use crate::vc::VCStatusesData;
use crate::vc::core::{
    FormatNotSupportedSnafu, InconsistentStatusListDataSnafu, InvalidDIDUrlSnafu, KMSSnafu, Result,
    StatusListCreatingSnafu,
};
use crate::vc::core::{StatusIssuer, StatusIssuerMetadata, StatusListDefinition};
use crate::vc::status_formats::API;
use crate::vc::status_formats::StatusListFormat;
use crate::vc::status_formats::status_list_token_jwt::StatusListJwt;
use async_trait::async_trait;
use snafu::ResultExt;
use ssi::dids::DIDURLBuf;
use std::marker::PhantomData;
use std::str::FromStr;
use tracing::{Level, debug, info, instrument, trace};

pub struct StatusIssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    kms: KMS,
    metadata: StatusIssuerMetadata,
    _marker: PhantomData<KH>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<KH, KMS> StatusIssuer for StatusIssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn issue_status_list(
        &self,
        status_list_id: &str,
        statuses: VCStatusesData,
    ) -> Result<StatusList> {
        // TODO: consider passing SLMetadata directly in the function
        let status_list_def = self
            .metadata
            .supported_status_lists
            .iter()
            .find(|item| item.id == status_list_id)
            .ok_or_else(|| {
                StatusListCreatingSnafu {
                    details: format!("Status list definition not found: {status_list_id}"),
                }
                .build()
            })?;

        let status_list = match status_list_def.format {
            StatusListFormat::StatusListTokenJwt(ref metadata) => {
                let VCStatusesData::StatusListToken(statuses) = statuses else {
                    return InconsistentStatusListDataSnafu {
                        details: "VCStatusesData::StatusListToken must be provided for StatusListFormat::StatusListTokenJwt issuance".to_string()
                    }.fail();
                };

                let (iss_did_url, iss_kh) = self.resolve_key_metadata(status_list_def).await?;

                let status =
                    StatusListJwt::create_status_list(statuses, (&iss_did_url, iss_kh), metadata)
                        .await
                        .map_err(|err| {
                            StatusListCreatingSnafu {
                                details: err.to_string(),
                            }
                            .build()
                        })?;

                StatusList::StatusListTokenJwt(status)
            }
            _ => {
                return FormatNotSupportedSnafu {
                    format: status_list_def.format.to_string(),
                }
                .fail();
            }
        };

        Ok(status_list)
    }
}

impl<KH, KMS> StatusIssuerService<KH, KMS>
where
    KH: kms::KeyHandle,
    KMS: kms::Kms<KH>,
{
    #[instrument(level = Level::TRACE, skip(kms))]
    pub fn new(kms: KMS, metadata: StatusIssuerMetadata) -> Self {
        Self {
            kms,
            metadata,
            _marker: Default::default(),
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err())]
    async fn resolve_key_metadata(
        &self,
        status_list_def: &StatusListDefinition,
    ) -> Result<(DIDURLBuf, KH)> {
        trace!(status_list_definition_id = ?status_list_def);

        let key_meta = &status_list_def.key_metadata;

        let did_url = DIDURLBuf::from_str(&key_meta.did_url).map_err(|err| {
            InvalidDIDUrlSnafu {
                input: format!("{}: {}", key_meta.did_url, err),
            }
            .build()
        })?;

        info!("access to the key {}", key_meta.kid);
        let kh = self.kms.get(&key_meta.kid).await.context(KMSSnafu)?;

        debug!(resolved_did_url = ?did_url);

        Ok((did_url, kh))
    }
}

#[cfg(test)]
mod tests {
    use super::StatusIssuerService;
    use crate::inmem::kms::LocalKms;
    use crate::utils::test_utils::create_did_and_key_metadata;
    use crate::vc::StatusList;
    use crate::vc::VCStatusesData;
    use crate::vc::core::api::StatusIssuer;
    use crate::vc::core::{StatusIssuerMetadata, StatusListDefinition};
    use crate::vc::presentation_exchange::StatusSize;
    use crate::vc::status_formats::StatusListFormat;
    use crate::vc::status_formats::status_list_token_jwt::{SLMetadata, VCStatus, VCStatuses};
    use std::str::FromStr;
    use url::Url;

    #[tokio::test]
    async fn status_list_issuance_works_correctly() {
        let kms = LocalKms::new();
        let (iss_did, key_metadata) = create_did_and_key_metadata(&kms).await;

        let metadata = StatusIssuerMetadata {
            issuer_id: iss_did,
            supported_status_lists: vec![StatusListDefinition {
                id: "test".to_string(),
                format: StatusListFormat::StatusListTokenJwt(SLMetadata {
                    statuses_nr: 32,
                    status_list_url: Url::from_str("http://example.com/status_list").unwrap(),
                    status_size: StatusSize::try_from(1u8).unwrap(),
                }),
                key_metadata,
            }],
        };

        let issuer = StatusIssuerService::new(kms, metadata);

        let mut statuses = VCStatuses::new();
        let vc_index: usize = 1;
        statuses.set(vc_index, VCStatus::Invalid);

        let status_list = issuer
            .issue_status_list("test", VCStatusesData::StatusListToken(statuses))
            .await
            .unwrap();

        let StatusList::StatusListTokenJwt(status_list_jwt) = status_list;

        let jwt_parts_iter: Vec<&str> = status_list_jwt.split('.').collect();

        let payload_b64 = jwt_parts_iter[1];
        let payload = crate::utils::b64::decode(payload_b64).unwrap();
        let payload = serde_json::Value::from_str(&String::from_utf8(payload).unwrap()).unwrap();

        assert_eq!(
            payload.get("status_list").unwrap(),
            &serde_json::json!({"lst": "eNpjYmBgAAAADAAD", "bits": 1}),
        );
    }
}
