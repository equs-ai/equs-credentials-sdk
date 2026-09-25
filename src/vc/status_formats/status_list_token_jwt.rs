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
use tracing::{Level, instrument, trace};

use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::utils::serde::get_time_based_claim;
use crate::vc::formats::API as VCFormatsAPI;
use crate::vc::formats::VerifyOptions;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::presentation_exchange::StatusSize;
use crate::vc::status_formats::API;
use crate::vc::status_formats::StatusListCreatingSnafu;
use flate2::Compression;
use oauth2::http;
use oauth2::http::Method;
use serde_json::Value;
use ssi_status::token_status_list::BitString;
use ssi_status::token_status_list::json::JsonStatusList;
use ssi_status::token_status_list::json::Status;
use strum_macros::Display;
use url::Url;

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
pub type StatusList = String;

/// # Status type values.
///
/// A status describes the state, mode, condition or stage of an entity that is described by the Status List.
///
/// # Variants:
/// - `0x00` "VALID": The status of the Token is valid, correct or legal.
/// - `0x01` "INVALID": The status of the Token is revoked, annulled, taken back, recalled or cancelled. This state is irreversible.
/// - `0x02` "SUSPENDED": The status of the Token is temporarily invalid, hanging, debarred from privilege. This state is reversible.
#[derive(Debug, Clone, Copy, Display, PartialEq)]
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

    pub fn statuses(&self) -> &HashMap<usize, u8> {
        &self.statuses
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SLMetadata {
    pub statuses_nr: usize,
    pub status_list_url: Url,
    pub status_size: StatusSize,
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

    #[instrument(level = Level::TRACE, skip(vc_claims, http_client, did_resolver), err(), ret())]
    async fn get_vc_status(
        vc_claims: &Claims,
        http_client: &dyn HttpClient,
        did_resolver: UniversalResolver,
        cached_urls_per_status_jwts: Option<&mut HashMap<String, String>>,
    ) -> Result<Option<VCStatus>> {
        StatusListJwt::get_vc_status_with_trusted_certs(
            vc_claims,
            http_client,
            did_resolver,
            cached_urls_per_status_jwts,
            None,
        )
        .await
    }
}

impl StatusListJwt {
    /// [API::get_vc_status], additionally trusting a status list token signed by an `x5c` chain
    /// that validates up to one of `trusted_certs`.
    #[instrument(
        level = Level::TRACE,
        skip(vc_claims, http_client, did_resolver, trusted_certs),
        err(),
        ret()
    )]
    pub async fn get_vc_status_with_trusted_certs(
        vc_claims: &Claims,
        http_client: &dyn HttpClient,
        did_resolver: UniversalResolver,
        mut cached_urls_per_status_jwts: Option<&mut HashMap<String, String>>,
        trusted_certs: Option<&HashMap<String, String>>,
    ) -> Result<Option<VCStatus>> {
        let Some(status_claim) = vc_claims.get(STATUS_CLAIM) else {
            return Ok(None);
        };

        let status_value = Value::try_from(status_claim.clone()).context(ClaimsSnafu)?;
        let status: Status = serde_json::from_value(status_value).context(ParseSnafu)?;

        let status_list_jwt = match cached_urls_per_status_jwts
            .as_ref()
            .and_then(|m| m.get(status.status_list.uri.as_str()).cloned())
        {
            Some(bitstring) => bitstring,
            _ => {
                StatusListJwt::fetch_bitstring_status_list_jwt(
                    http_client,
                    status.status_list.uri.as_str(),
                )
                .await?
            }
        };

        let status_list = StatusListJwt::extract_bitstring_status_list(
            status.status_list.uri.as_str(),
            did_resolver,
            status_list_jwt.clone(),
            trusted_certs,
        )
        .await?;
        let cred_status = status_list.get(status.status_list.idx).ok_or_else(|| {
            VCStatusSnafu {
                details: format!("failed to get index {}", status.status_list.idx),
            }
            .build()
        })?;

        cached_urls_per_status_jwts
            .as_mut()
            .map(|m| m.insert(status.status_list.uri.as_str().to_string(), status_list_jwt));

        Ok(Some(cred_status.into()))
    }

    #[instrument(level = Level::TRACE, err())]
    fn create_json_status_list(
        statuses: &VCStatuses,
        metadata: &SLMetadata,
    ) -> Result<JsonStatusList> {
        let mut bit_string = BitString::new_zeroed(metadata.status_size, metadata.statuses_nr);

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
    async fn fetch_bitstring_status_list_jwt(
        http_client: &dyn HttpClient,
        url: &str,
    ) -> Result<String> {
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

        Ok(status_list_sdjwt_vc)
    }

    #[instrument(level = Level::TRACE, skip(did_resolver, trusted_certs), err(), ret())]
    async fn extract_bitstring_status_list(
        url: &str,
        did_resolver: UniversalResolver,
        status_list_sdjwt_vc: String,
        trusted_certs: Option<&HashMap<String, String>>,
    ) -> Result<BitString> {
        let claims = StatusListJwt::decode_status_list_token(&status_list_sdjwt_vc)?;

        let opts = VerifyOptions {
            trusted_certs: trusted_certs.cloned(),
            ..Default::default()
        };
        SdJwtAPI::verify_vc(&status_list_sdjwt_vc, opts, did_resolver) // TODO: consider using sd_jwt API directly
            .await
            .map_err(|err| {
                VCStatusSnafu {
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

    /// Decodes the claims of a status list token without verifying it.
    #[instrument(level = Level::TRACE, skip(status_list_token), err())]
    fn decode_status_list_token(status_list_token: &str) -> Result<Claims> {
        let jwt = status_list_token.split('~').next().unwrap_or_default();
        let (header, payload) = ssi::claims::jws::decode_unverified(jwt).map_err(|err| {
            MalformedStatusListSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        if header.type_.as_deref() != Some(STATUS_LIST_TYPE) {
            return MalformedStatusListSnafu {
                details: format!("expected `typ` {STATUS_LIST_TYPE}, got {:?}", header.type_),
            }
            .fail();
        }

        let claims: Value = serde_json::from_slice(&payload).context(ParseSnafu)?;
        claims.try_into().context(ClaimsSnafu)
    }
}

#[cfg(test)]
mod tests {
    use super::{SLMetadata, StatusListJwt, VCStatus, VCStatuses};
    use crate::did::universal::UniversalResolver;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::kms::KeyType;
    use crate::utils::http::test::mock_http_fn_with_plain_text_resp;
    use crate::utils::test_utils::create_did_url_and_key_handle;
    use crate::vc::presentation_exchange::StatusSize;
    use crate::vc::status_formats::API;
    use oauth2::http::Method;
    use rstest::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::str::FromStr;
    use url::Url;

    fn single_bit_statuses() -> VCStatuses {
        let mut statuses = VCStatuses::new();
        statuses.set(1, VCStatus::Invalid);
        statuses
    }

    fn two_bit_statuses() -> VCStatuses {
        let mut statuses = VCStatuses::new();
        statuses.set(1, VCStatus::Valid);
        statuses.set(2, VCStatus::Invalid);
        statuses.set(3, VCStatus::Suspended);
        statuses.set(4, VCStatus::AppSpecific(3));
        statuses
    }

    #[rstest]
    #[case::bit_size_1(1u8, single_bit_statuses(), json!({"lst": "eNpjYmBgAAAADAAD", "bits": 1}))]
    #[case::bit_size_2(2u8, two_bit_statuses(), json!({"lst": "eNqbwMwABgAEnQCU", "bits": 2}))]
    #[tokio::test]
    async fn status_list_is_created_correctly(
        #[case] status_bit_size: u8,
        #[case] statuses: VCStatuses,
        #[case] expected_payload: serde_json::Value,
    ) {
        let (iss_did, key_handle) =
            create_did_url_and_key_handle(&LocalKms::new(), KeyType::P256).await;

        let metadata = SLMetadata {
            statuses_nr: 32,
            status_list_url: Url::from_str("http://example.com/status_list").unwrap(),
            status_size: StatusSize::try_from(status_bit_size).unwrap(),
        };

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
        assert_eq!(payload.get("status_list").unwrap(), &expected_payload,);
    }

    #[rstest]
    #[case::one_bit_valid(1, status_list_jwt_token_1bit(), VCStatus::Valid)]
    #[case::one_bit_invalid(2, status_list_jwt_token_1bit(), VCStatus::Invalid)]
    #[case::two_bit_valid(1, status_list_jwt_token_2bit(), VCStatus::Valid)]
    #[case::two_bit_invalid(2, status_list_jwt_token_2bit(), VCStatus::Invalid)]
    #[case::two_bit_suspended(3, status_list_jwt_token_2bit(), VCStatus::Suspended)]
    #[case::two_bit_app_specific(4, status_list_jwt_token_2bit(), VCStatus::AppSpecific(3))]
    #[tokio::test]
    async fn vc_status_is_validated_correctly(
        #[case] vc_index: usize,
        #[case] status_list_token: &str,
        #[case] expected_status: VCStatus,
    ) {
        let mut http_client = MockHttpClient::new();

        mock_http_fn_with_plain_text_resp(
            &mut http_client,
            Method::GET,
            Url::from_str("http://example.com/status_list").unwrap(),
            status_list_jwt_token_2bit(),
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

        let vc_status =
            StatusListJwt::get_vc_status(&claims, &http_client, UniversalResolver::default(), None)
                .await
                .unwrap();

        assert_eq!(vc_status, Some(expected_status));
    }

    #[tokio::test]
    async fn vc_status_is_validated_correctly_when_cached_status_list_jwt_is_used() {
        let mut http_client = MockHttpClient::new();
        let url = "http://example.com/status_list";

        mock_http_fn_with_plain_text_resp(
            &mut http_client,
            Method::GET,
            Url::from_str(url).unwrap(),
            status_list_jwt_token_1bit(),
            1.into(),
        );

        let claims = json!({
            "status": {
                "status_list": {
                    "idx": 1,
                    "uri": url
                }
            }
        })
        .try_into()
        .unwrap();

        let mut cached_jwts = HashMap::new();
        let vc_status = StatusListJwt::get_vc_status(
            &claims,
            &http_client,
            UniversalResolver::default(),
            Some(&mut cached_jwts),
        )
        .await
        .unwrap();

        assert_eq!(vc_status, Some(VCStatus::Invalid));
        assert_eq!(cached_jwts.len(), 1);
        assert_eq!(cached_jwts.get(url).unwrap(), status_list_jwt_token_1bit());

        // Second call with same URL should use cached status list JWT
        http_client = MockHttpClient::new();
        let vc_status = StatusListJwt::get_vc_status(
            &claims,
            &http_client,
            UniversalResolver::default(),
            Some(&mut cached_jwts),
        )
        .await
        .unwrap();

        assert_eq!(vc_status, Some(VCStatus::Invalid));
    }

    const X5C_STATUS_LIST_URL: &str = "https://status.example/status_list";

    async fn x5c_status_of(
        token: &'static str,
        idx: usize,
        trusted_certs: Option<HashMap<String, String>>,
    ) -> crate::vc::status_formats::Result<Option<VCStatus>> {
        let mut http_client = MockHttpClient::new();
        mock_http_fn_with_plain_text_resp(
            &mut http_client,
            Method::GET,
            Url::from_str(X5C_STATUS_LIST_URL).unwrap(),
            token,
            1.into(),
        );
        let claims =
            json!({ "status": { "status_list": { "idx": idx, "uri": X5C_STATUS_LIST_URL } } })
                .try_into()
                .unwrap();

        StatusListJwt::get_vc_status_with_trusted_certs(
            &claims,
            &http_client,
            UniversalResolver::default(),
            None,
            trusted_certs.as_ref(),
        )
        .await
    }

    #[rstest]
    #[case::invalid(2, VCStatus::Invalid)]
    #[case::suspended(3, VCStatus::Suspended)]
    #[tokio::test]
    async fn x5c_signed_status_list_is_verified_against_a_trusted_anchor(
        #[case] idx: usize,
        #[case] expected_status: VCStatus,
    ) {
        let token = x5c_signed_status_list("statuslist+jwt", true);

        let vc_status = x5c_status_of(token, idx, Some(anchors(&[STATUS_LIST_ROOT_CA])))
            .await
            .unwrap();

        assert_eq!(vc_status, Some(expected_status));
    }

    #[rstest]
    #[case::no_trusted_anchors(None)]
    #[case::unrelated_anchor(Some(anchors(&[UNRELATED_ROOT_CA])))]
    #[tokio::test]
    async fn x5c_signed_status_list_is_rejected_without_its_anchor(
        #[case] trusted_certs: Option<HashMap<String, String>>,
    ) {
        let token = x5c_signed_status_list("statuslist+jwt", true);

        let error = x5c_status_of(token, 2, trusted_certs)
            .await
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("Certificate chain is not trusted"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn status_list_with_unexpected_typ_is_rejected() {
        let token = x5c_signed_status_list("JWT", true);

        let error = x5c_status_of(token, 2, Some(anchors(&[STATUS_LIST_ROOT_CA])))
            .await
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("Malformed status list"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn status_list_without_a_key_source_is_rejected() {
        let token = x5c_signed_status_list("statuslist+jwt", false);

        let error = x5c_status_of(token, 2, Some(anchors(&[STATUS_LIST_ROOT_CA])))
            .await
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("no DID URL `kid`, `x5c` certificate chain or `iss` claim"),
            "unexpected error: {error}"
        );
    }

    fn x5c_signed_status_list(typ: &str, with_x5c: bool) -> &'static str {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some(typ.to_string());
        if with_x5c {
            header.x5c =
                Some(one_core::mapper::x509::pem_chain_into_x5c(STATUS_LIST_SIGNER_CERT).unwrap());
        }
        let claims = json!({
            "sub": X5C_STATUS_LIST_URL,
            "iat": 1790000000,
            "status_list": { "bits": 2, "lst": "eNqbwMwABgAEnQCU" }
        });
        let key =
            jsonwebtoken::EncodingKey::from_ec_pem(STATUS_LIST_SIGNER_KEY.as_bytes()).unwrap();

        Box::leak(
            jsonwebtoken::encode(&header, &claims, &key)
                .unwrap()
                .into_boxed_str(),
        )
    }

    /// Trusted anchors keyed by Subject Key Identifier, as the verifier holds them.
    fn anchors(ca_certs: &[&str]) -> HashMap<String, String> {
        ca_certs
            .iter()
            .map(|ca_cert| {
                let pem = x509_parser::prelude::Pem::iter_from_buffer(ca_cert.as_bytes())
                    .next()
                    .unwrap()
                    .unwrap();
                let skid =
                    one_core::mapper::x509::subject_key_identifier(&pem.parse_x509().unwrap())
                        .unwrap()
                        .unwrap();
                (skid, ca_cert.to_string())
            })
            .collect()
    }

    /// Self-signed test CA; issued [STATUS_LIST_SIGNER_CERT]. Valid until 2046.
    const STATUS_LIST_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBpDCCAUqgAwIBAgIUCkemKWp/mEZWOriUweY1x6kqPnIwCgYIKoZIzj0EAwIw
MDEhMB8GA1UEAwwYVGVzdCBTdGF0dXMgTGlzdCBSb290IENBMQswCQYDVQQGEwJV
UzAeFw0yNjA5MjUxMzI4MTFaFw00NjA5MjAxMzI4MTFaMDAxITAfBgNVBAMMGFRl
c3QgU3RhdHVzIExpc3QgUm9vdCBDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATh1JjKx3hq3ZIjK6G6pBeHiwdiyXiYu+ZmufaCF4sa+/qu
Qa13rjydhWVf21XAn8ojKupFyHumcgn/9ViYI6joo0IwQDAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUzipg2dTWTUqNtW0A6EsQFt7b
CswwCgYIKoZIzj0EAwIDSAAwRQIhALEaQwSxB5oUvfqlvZsUf9uqWyByr5BfTkqS
daRDuYTCAiBxntj1WL8RYNzD2KDI6DCepwhUE/H+dilH7LO3hM6xUA==
-----END CERTIFICATE-----";
    /// Leaf issued by [STATUS_LIST_ROOT_CA]: SAN `DNS:status.example`, key usage
    /// `digitalSignature`. Valid until 2046.
    const STATUS_LIST_SIGNER_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIB3TCCAYKgAwIBAgIUfbmn1g8zvFqJaGe6Siq4QcNyOnYwCgYIKoZIzj0EAwIw
MDEhMB8GA1UEAwwYVGVzdCBTdGF0dXMgTGlzdCBSb290IENBMQswCQYDVQQGEwJV
UzAeFw0yNjA5MjUxMzI4MTFaFw00NjA5MTkxMzI4MTFaMC8xIDAeBgNVBAMMF1Rl
c3QgU3RhdHVzIExpc3QgU2lnbmVyMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABFh6TAqdE0bBRG+96eSRq0ejV8i8g9T9qcZn159gB2+SpNVA
zJcnmzoPOfYWGKQDBtDsx8NiOEmMrFSOsa29+2qjezB5MAwGA1UdEwEB/wQCMAAw
DgYDVR0PAQH/BAQDAgeAMBkGA1UdEQQSMBCCDnN0YXR1cy5leGFtcGxlMB0GA1Ud
DgQWBBR8ppolkTgua/w2aJimDuROUiOq3jAfBgNVHSMEGDAWgBTOKmDZ1NZNSo21
bQDoSxAW3tsKzDAKBggqhkjOPQQDAgNJADBGAiEAq05h7Rp5R2aeWuyHB1ZVqjXx
Tf22elmDq7rWTOTxshwCIQDsHXngYDUmOslw/JjAK2vqYldLIE49FPyyW7WLpLP1
Ag==
-----END CERTIFICATE-----";
    /// Test-only private key of [STATUS_LIST_SIGNER_CERT] (PKCS#8, P-256).
    const STATUS_LIST_SIGNER_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKmNBunWjEFqhGhn4
G4Oq22ahs02HcCEGTiUcztmr+c+hRANCAARYekwKnRNGwURvvenkkatHo1fIvIPU
/anGZ9efYAdvkqTVQMyXJ5s6Dzn2FhikAwbQ7MfDYjhJjKxUjrGtvftq
-----END PRIVATE KEY-----";
    /// Self-signed test CA unrelated to [STATUS_LIST_SIGNER_CERT]. Valid until 2046.
    const UNRELATED_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBoDCCAUagAwIBAgIUbh8l2hryhw1EPW3aNxmlPRYQb/kwCgYIKoZIzj0EAwIw
LjEfMB0GA1UEAwwWVW5yZWxhdGVkIFRlc3QgUm9vdCBDQTELMAkGA1UEBhMCVVMw
HhcNMjYwOTI1MTMyODI4WhcNNDYwOTIwMTMyODI4WjAuMR8wHQYDVQQDDBZVbnJl
bGF0ZWQgVGVzdCBSb290IENBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABPfNzFQzAznejGJv/AUkaNxxafUF9Hdy5pzrh+ixSqBPPacly9R7
ERsMqQtcpIcsPqz9stGaV37vZ/ZRV/vSGsOjQjBAMA8GA1UdEwEB/wQFMAMBAf8w
DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTC86sBx3jik76wJkXhXmQGtPFrUTAK
BggqhkjOPQQDAgNIADBFAiEAhKLv5TB6lpDfRyh/ymK4DfikOKIlj666bVwNwdsU
ycICIFoqyd8bcLA/OZ+UAdisSzWFg0z7XLHwFFwj1G+di+Xq
-----END CERTIFICATE-----";

    /// Status list token that contains the following status list:
    /// token idx - status:
    /// 1 - Valid
    /// 2 - Invalid
    ///
    /// Status bit size - 1
    fn status_list_jwt_token_1bit() -> &'static str {
        "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZG\
         lkOmtleTp6RG5hZWRlaHVUUVdzNWhaZHFKTVJzZGRpa2RBUnl4OGZhYzI4UjRN\
         UFVRRTIybnhaI3pEbmFlZGVodVRRV3M1aFpkcUpNUnNkZGlrZEFSeXg4ZmFjMj\
         hSNE1QVVFFMjJueFoifQ.eyJzdGF0dXNfbGlzdCI6eyJsc3QiOiJlTnBqWW1CZ\
         0FBQUFEQUFEIiwiYml0cyI6MX0sImlhdCI6MTczODA3NDEzMCwic3ViIjoiaHR\
         0cDovL2V4YW1wbGUuY29tL3N0YXR1c19saXN0IiwiX3NkX2FsZyI6InNoYS0yN\
         TYifQ.HlkzOlNu8fNpLgHxfX0Ra7J1AqxxPwlyiskhMFaSfbVymoWRvHNuadT1\
         PFr92AogZsMI5wHJkIBrBIOVdlfr3g~"
    }

    /// Status list token that contains the following status list:
    /// token idx - status:
    /// 1 - Valid
    /// 2 - Invalid
    /// 3 - Suspended
    /// 4 - AppSpecific (value - 3)
    ///
    /// Status bit size - 2
    fn status_list_jwt_token_2bit() -> &'static str {
        "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmtleTp6R\
        G5hZWFoVE5nRVozN0ZESlRQcFhUWDJRUFBWb21nc2k4QVMzMjFjMjRNMlVvNWQ2I3pEbmFlYWh\
        UTmdFWjM3RkRKVFBwWFRYMlFQUFZvbWdzaThBUzMyMWMyNE0yVW81ZDYifQ.eyJzdWIiOiJodH\
        RwOi8vZXhhbXBsZS5jb20vc3RhdHVzX2xpc3QiLCJpYXQiOjE3NjMwMjQ0MTYsInN0YXR1c19s\
        aXN0Ijp7ImxzdCI6ImVOcWJ3TXdBQmdBRW5RQ1UiLCJiaXRzIjoyfSwiX3NkX2FsZyI6InNoYS\
        0yNTYifQ.uxeAWNaz0sP2PHrp3xndbrmNQTrHiGycOwsiGX4f1nsYGcLZhYmsTP5ixcdxWvTq3\
        9blTkiRt1wXnCESlxqboQ~"
    }
}
