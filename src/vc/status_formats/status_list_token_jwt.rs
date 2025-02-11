//! Token Status List Spec implementations.

use crate::crypto::Signer;
use crate::did::DIDURL;
use crate::vc::claims::{Claim, Claims};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::vc::formats::sd_jwt_vc::SignerWrapper;
use crate::vc::status_formats::ParseSnafu;
use crate::vc::status_formats::Result;

use crate::utils::serde::Helpers;
use crate::vc::status_formats::{
    ClaimsSnafu, MalformedStatusListSnafu, SigningSnafu, StatusListFetchingSnafu, VCStatusSnafu,
};
use snafu::ResultExt;

use sd_jwt_rs::{ClaimsForSelectiveDisclosureStrategy, SDJWTIssuer, SDJWTSerializationFormat};
use std::collections::HashMap;
use tracing::{instrument, trace, Level};

use crate::http::HttpClient;
use crate::utils::serde::get_time_based_claim;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::formats::VerifyOptions;
use crate::vc::formats::API as VCFormatsAPI;
use crate::vc::status_formats::API;
use crate::vc::HasClaims;
use flate2::Compression;
use oauth2::http;
use oauth2::http::Method;
use serde_json::Value;
use ssi_status::token_status_list::json::JsonStatusList;
use ssi_status::token_status_list::json::Status;
use ssi_status::token_status_list::{BitString, StatusSize};
use strum_macros::Display;
use url::Url;

use crate::vc::status_formats::StatusListCreatingSnafu;

// TODO: consider moving the constants in some common module
// to share them between SdJwtVc format as well
const EXP_CLAIM: &str = "exp";
const IAT_CLAIM: &str = "iat";
const SUB_CLAIM: &str = "sub";
const TYP_CLAIM: &str = "typ";
const KID_CLAIM: &str = "kid";
const STATUS_CLAIM: &str = "status";

const STATUS_LIST_TYPE: &str = "statuslist+jwt";
const CONTENT_TYPE_HEADER: &str = "application/statuslist+jwt";
const DEFAULT_STATUS_SIZE: u8 = 1;

pub type StatusList = String;

/// # Status type values.
///
/// A status describes the state, mode, condition or stage of an entity that is described by the Status List.
///
/// # Variants:
/// - `0x00` "VALID": The status of the Token is valid, correct or legal.
/// - `0x01` "INVALID": The status of the Token is revoked, annulled, taken back, recalled or cancelled. This state is irreversible.
/// - `0x02` "SUSPENDED": The status of the Token is temporarily invalid, hanging, debarred from privilege. This state is reversible.
#[derive(Debug, Display, PartialEq)]
pub enum VCStatus {
    Valid,
    Invalid,
    Suspended,
    AppSpecific(u8),
}

impl From<VCStatus> for u8 {
    #[instrument(level = Level::TRACE, ret())]
    fn from(status: VCStatus) -> Self {
        match status {
            VCStatus::Valid => 0x00,
            VCStatus::Invalid => 0x01,
            VCStatus::Suspended => 0x02,
            VCStatus::AppSpecific(val) => val,
        }
    }
}

impl From<u8> for VCStatus {
    #[instrument(level = Level::TRACE, ret())]
    fn from(val: u8) -> Self {
        match val {
            0x00 => VCStatus::Valid,
            0x01 => VCStatus::Invalid,
            0x02 => VCStatus::Suspended,
            _ => VCStatus::AppSpecific(val), // TODO: check if the values 0x10...0xff comply with the standard
        }
    }
}

/// # VC Statuses
///
/// This structure represents a **Status List** used to track the status of Verifiable Credentials.
///
/// # Fields
///
/// - `statuses`: is a **hash map** where:
///   - `key`: represents the **index** of a credential in the status list.
///   - `value`: represents the **status code** (e.g., `VALID`, `INVALID`, `SUSPENDED`).
///
///
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VCStatuses {
    pub(crate) statuses: HashMap<usize, u8>,
}

impl VCStatuses {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new() -> Self {
        Self {
            statuses: HashMap::new(),
        }
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn set(&mut self, index: usize, status: VCStatus) {
        self.statuses.insert(index, status.into());
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SLMetadata {
    pub statuses_nr: usize,
    pub status_list_url: Url,
    // pub lifetime: time::Duration, // TODO:
}

pub struct StatusListJwt;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl API<VCStatus, VCStatuses, StatusList, SLMetadata> for StatusListJwt {
    #[instrument(level = Level::TRACE, skip(issuer_data), err(), ret())]
    async fn create_status_list<S>(
        statuses: VCStatuses,
        issuer_data: (&DIDURL, S),
        metadata: &SLMetadata,
    ) -> Result<StatusList>
    where
        S: Signer,
    {
        trace!(issuer_did_url = ?{issuer_data.0});

        let (iss_did_url, signer) = issuer_data;
        let sgn_wrapper = SignerWrapper { signer };
        let status_list = StatusListJwt::create_json_status_list(&statuses, metadata)?;
        let claims = StatusListJwt::prepare_claims(
            status_list,
            metadata.status_list_url.as_str(),
            metadata,
        )?;
        let headers = StatusListJwt::extra_headers(iss_did_url);
        trace!(resolved_headers = ?headers);

        let mut issuer = SDJWTIssuer::new(sgn_wrapper);
        let claims = claims.try_into().context(ClaimsSnafu)?;

        issuer
            .issue_sd_jwt(
                claims,
                ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
                None,
                false,
                SDJWTSerializationFormat::Compact,
                Some(headers),
            )
            .await
            .map_err(|err| {
                SigningSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    async fn get_vc_status(
        vc_claims: &Claims,
        http_client: &dyn HttpClient,
    ) -> Result<Option<VCStatus>> {
        let Some(status_claim) = vc_claims.get(STATUS_CLAIM) else {
            return Ok(None);
        };

        let status_value = Value::try_from(status_claim.clone()).context(ClaimsSnafu)?;
        let status: Status = serde_json::from_value(status_value).context(ParseSnafu)?;

        let bit_string = StatusListJwt::fetch_bitstring_status_list(
            http_client,
            status.status_list.uri.as_str(),
        )
        .await?;

        let cred_status = bit_string.get(status.status_list.idx).ok_or_else(|| {
            VCStatusSnafu {
                details: format!("failed to get index {}", status.status_list.idx),
            }
            .build()
        })?;

        Ok(Some(cred_status.into()))
    }
}

impl StatusListJwt {
    #[instrument(level = Level::TRACE, err())]
    fn create_json_status_list(
        statuses: &VCStatuses,
        metadata: &SLMetadata,
    ) -> Result<JsonStatusList> {
        let status_size: StatusSize = StatusSize::try_from(DEFAULT_STATUS_SIZE).map_err(|err| {
            StatusListCreatingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let mut bit_string = BitString::new_zeroed(status_size, metadata.statuses_nr);

        for (index, value) in statuses.statuses.iter() {
            bit_string.set(*index, *value).map_err(|err| {
                StatusListCreatingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;
        }

        let status_list = JsonStatusList::encode(&bit_string, Compression::best());
        Ok(status_list)
    }

    #[instrument(level = Level::TRACE, skip(status_list), err(), ret())]
    fn prepare_claims(
        status_list: JsonStatusList,
        sub: &str,
        metadata: &SLMetadata,
    ) -> Result<Claims> {
        let mut claims = Claims::new();
        claims.put_str(SUB_CLAIM, sub);

        let iat =
            get_time_based_claim(&claims, IAT_CLAIM).unwrap_or_else(time::OffsetDateTime::now_utc);
        claims.put_dt(IAT_CLAIM, iat);

        // let exp = Self::get_expiration_claim(&claims)
        //     .unwrap_or_else(|| time::OffsetDateTime::now_utc() + metadata.lifetime);
        // claims.put_dt(EXP_CLAIM, exp);

        let json_status_list_value = serde_json::to_value(status_list).map_err(|err| {
            StatusListCreatingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        claims.insert("status_list".to_string(), json_status_list_value.into());

        Ok(claims)
    }

    #[instrument(level = Level::TRACE, ret())]
    fn extra_headers(iss_did_url: &DIDURL) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(TYP_CLAIM.to_string(), STATUS_LIST_TYPE.to_string());
        headers.insert(KID_CLAIM.to_string(), iss_did_url.to_string());

        headers
    }

    #[instrument(level = Level::TRACE, skip(http_client), err(), ret())]
    async fn fetch_bitstring_status_list(
        http_client: &dyn HttpClient,
        url: &str,
    ) -> Result<BitString> {
        let http_req = http::request::Builder::new()
            .uri(url)
            .method(Method::GET)
            .header(oauth2::http::header::ACCEPT, CONTENT_TYPE_HEADER)
            .body(vec![])
            .map_err(|err| {
                StatusListFetchingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        let status_list_sdjwt_vc = http_client.async_call(http_req).await.map_err(|err| {
            StatusListFetchingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let status_list_sdjwt_vc =
            String::from_utf8(status_list_sdjwt_vc.body().clone()).map_err(|err| {
                StatusListFetchingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        SdJwtAPI::verify_vc(
            &status_list_sdjwt_vc,
            VerifyOptions {
                selective_claims: None,
            },
        ) // TODO: consider using sd_jwt API directly
        .await
        .map_err(|err| {
            VCStatusSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let claims = status_list_sdjwt_vc.parse_claims().map_err(|err| {
            StatusListFetchingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let Some(sub) = claims.get(SUB_CLAIM) else {
            return MalformedStatusListSnafu {
                details: "Missed the 'sub' field",
            }
            .fail();
        };

        let Claim::String(sub_str) = sub else {
            return MalformedStatusListSnafu {
                details: "The 'sub' field must be a URL",
            }
            .fail();
        };

        if sub_str != url {
            return VCStatusSnafu {
                details: format!("Urls are not equal {url} {sub_str}"),
            }
            .fail();
        }

        let Some(status_list) = claims.get("status_list") else {
            return MalformedStatusListSnafu {
                details: "missed the 'status_list' field",
            }
            .fail();
        };

        let status_list_value = Value::try_from(status_list.clone()).map_err(|err| {
            MalformedStatusListSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let json_status_list: JsonStatusList =
            serde_json::from_value(status_list_value).map_err(|err| {
                MalformedStatusListSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        let bit_string = json_status_list.decode(None).map_err(|err| {
            MalformedStatusListSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(bit_string)
    }
}

#[cfg(test)]
mod tests {

    use super::{SLMetadata, StatusListJwt, VCStatus, VCStatuses};
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::kms::KeyType;
    use crate::utils::http::test::mock_http_fn_with_plain_text_resp;
    use crate::utils::test_utils::create_did_url_and_key_handle;
    use crate::vc::status_formats::API;
    use oauth2::http::Method;
    use rstest::rstest;
    use serde_json::json;
    use std::str::FromStr;
    use url::Url;

    #[tokio::test]
    async fn status_list_is_created_correctly() {
        let (iss_did, key_handle) =
            create_did_url_and_key_handle(&LocalKms::new(), KeyType::P256).await;

        let metadata = SLMetadata {
            statuses_nr: 32,
            status_list_url: Url::from_str("http://example.com/status_list").unwrap(),
        };

        let mut statuses = VCStatuses::new();
        let vc_index: usize = 1;
        statuses.set(vc_index, VCStatus::Invalid);

        let status_list_jwt =
            StatusListJwt::create_status_list(statuses, (&iss_did, key_handle), &metadata)
                .await
                .unwrap();

        let mut jwt_parts_iter = status_list_jwt.split('.');

        let header_b64 = jwt_parts_iter.next().unwrap();
        let payload_b64 = jwt_parts_iter.next().unwrap();

        let header = crate::utils::b64::decode(header_b64).unwrap();
        let header = serde_json::Value::from_str(&String::from_utf8(header).unwrap()).unwrap();

        let payload = crate::utils::b64::decode(payload_b64).unwrap();
        let payload = serde_json::Value::from_str(&String::from_utf8(payload).unwrap()).unwrap();

        assert_eq!(header.get("typ").unwrap().clone(), json!("statuslist+jwt"));
        assert_eq!(
            payload.get("sub").unwrap(),
            &json!("http://example.com/status_list")
        );
        assert!(payload.get("iat").is_some());
        assert_eq!(
            payload.get("status_list").unwrap(),
            &serde_json::json!({"lst": "eNpjYmBgAAAADAAD", "bits": 1}),
        );
    }

    #[rstest]
    #[case(1, VCStatus::Invalid)]
    #[case(2, VCStatus::Valid)]
    #[tokio::test]
    async fn vc_status_is_validated_correctly(
        #[case] vc_index: usize,
        #[case] expected_status: VCStatus,
    ) {
        let mut http_client = MockHttpClient::new();

        mock_http_fn_with_plain_text_resp(
            &mut http_client,
            Method::GET,
            Url::from_str("http://example.com/status_list").unwrap(),
            status_list_token_jwt_with_revoked_idx_1(),
            1.into(),
        );

        let claims = json!({
            "status": {
                "status_list": {
                    "idx": vc_index,
                    "uri": "http://example.com/status_list"
                }
            }
        })
        .try_into()
        .unwrap();

        let vc_status = StatusListJwt::get_vc_status(&claims, &http_client)
            .await
            .unwrap();

        assert_eq!(vc_status, Some(expected_status));
    }

    fn status_list_token_jwt_with_revoked_idx_1() -> &'static str {
        "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZG\
         lkOmtleTp6RG5hZWRlaHVUUVdzNWhaZHFKTVJzZGRpa2RBUnl4OGZhYzI4UjRN\
         UFVRRTIybnhaI3pEbmFlZGVodVRRV3M1aFpkcUpNUnNkZGlrZEFSeXg4ZmFjMj\
         hSNE1QVVFFMjJueFoifQ.eyJzdGF0dXNfbGlzdCI6eyJsc3QiOiJlTnBqWW1CZ\
         0FBQUFEQUFEIiwiYml0cyI6MX0sImlhdCI6MTczODA3NDEzMCwic3ViIjoiaHR\
         0cDovL2V4YW1wbGUuY29tL3N0YXR1c19saXN0IiwiX3NkX2FsZyI6InNoYS0yN\
         TYifQ.HlkzOlNu8fNpLgHxfX0Ra7J1AqxxPwlyiskhMFaSfbVymoWRvHNuadT1\
         PFr92AogZsMI5wHJkIBrBIOVdlfr3g~"
    }
}
