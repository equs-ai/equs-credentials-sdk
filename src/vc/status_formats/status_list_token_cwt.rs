//! Reads CWT Status List Tokens (draft-ietf-oauth-status-list §5.2), the status list format
//! used by mdoc credentials. The token checks are in [crate::vc::status_formats::cwt].

use std::collections::HashMap;

use coset::cbor::value::Value;
use ssi::status::token_status_list::BitString;
use tracing::{Level, instrument};

use crate::vc::formats::AnchorPolicy;
use crate::vc::presentation_exchange::StatusSize;
use crate::vc::status_formats::Result;
use crate::vc::status_formats::cwt::{self, CwtProfile, claim, malformed};

/// Media type and `typ` header of a CWT Status List Token.
pub(crate) const STATUS_LIST_CWT_TYPE: &str = "application/statuslist+cwt";

const STATUS_LIST_CLAIM: i64 = 65533;

const PROFILE: CwtProfile = CwtProfile {
    name: "status list",
    media_type: STATUS_LIST_CWT_TYPE,
    coap_id: Some(279),
};

pub(crate) struct StatusListCwt;

impl StatusListCwt {
    /// Verifies the CWT `token` fetched from `uri` and returns its status list.
    #[instrument(level = Level::TRACE, skip(token, trusted_certs), err())]
    pub(crate) async fn extract_status_list(
        uri: &str,
        token: &[u8],
        trusted_certs: Option<&HashMap<String, String>>,
        anchor_policy: AnchorPolicy,
    ) -> Result<BitString> {
        let claims = cwt::verify(&PROFILE, uri, token, trusted_certs, anchor_policy).await?;
        status_list(&claims)
    }
}

fn status_list(claims: &[(Value, Value)]) -> Result<BitString> {
    let Some(Value::Map(status_list)) = claim(claims, STATUS_LIST_CLAIM) else {
        return Err(malformed("missed the `status_list` claim"));
    };
    let field = |name: &str| {
        status_list
            .iter()
            .find(|(key, _)| key.as_text() == Some(name))
            .map(|(_, value)| value)
    };

    let bits = field("bits")
        .and_then(Value::as_integer)
        .and_then(|bits| u8::try_from(bits).ok())
        .ok_or_else(|| malformed("`status_list.bits` must be 1, 2, 4 or 8"))?;
    let bits = StatusSize::try_from(bits).map_err(|err| malformed(err.to_string()))?;
    let lst = field("lst")
        .and_then(Value::as_bytes)
        .ok_or_else(|| malformed("`status_list.lst` must be a byte string"))?;

    BitString::from_compressed_bytes(bits, lst, None).map_err(|err| malformed(err.to_string()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::StatusListCwt;
    use crate::utils::test_utils::anchors;
    use crate::vc::formats::AnchorPolicy;
    use crate::vc::status_formats::status_list_token_jwt::tests::{
        status_list_root_ca, status_list_signer_cert,
    };
    use rstest::rstest;
    use serde_json::{Value, json};
    use std::collections::HashMap;

    const URI: &str = "https://status.example/mdoc/1";

    /// Entries: 0 and 1 valid, 2 invalid, 3 suspended, 4 application-specific (3).
    const TWO_BIT_LST: &str = "eNqbwMwABgAEnQCU";

    fn spec(sub: &str) -> Value {
        json!({
            "sub": sub,
            "iat": 1790000000,
            "exp": 2200000000i64,
            "ttl": 43200,
            "bits": 2,
            "lst": TWO_BIT_LST,
            "typ": "application/statuslist+cwt",
            "x5chain": status_list_signer_cert(),
        })
    }

    /// A CWT status list for `sub`, signed under [status_list_root_ca].
    /// Entries: 0 and 1 valid, 2 invalid, 3 suspended.
    pub(crate) fn x5c_status_list_cwt(sub: &str) -> Vec<u8> {
        test_fixtures::status_list_cwt(&spec(sub), &test_fixtures::keys().issuer)
    }

    fn cwt_with(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut spec = spec(URI);
        edit(&mut spec);
        test_fixtures::status_list_cwt(&spec, &test_fixtures::keys().issuer)
    }

    fn trusted() -> Option<HashMap<String, String>> {
        Some(anchors(&[status_list_root_ca()]))
    }

    async fn entry(
        token: &[u8],
        idx: usize,
        trusted_certs: Option<HashMap<String, String>>,
    ) -> crate::vc::status_formats::Result<Option<u8>> {
        StatusListCwt::extract_status_list(
            URI,
            token,
            trusted_certs.as_ref(),
            AnchorPolicy::Require,
        )
        .await
        .map(|list| list.get(idx))
    }

    async fn error_of(token: Vec<u8>, trusted_certs: Option<HashMap<String, String>>) -> String {
        entry(&token, 0, trusted_certs)
            .await
            .unwrap_err()
            .to_string()
    }

    fn assert_contains(error: &str, expected: &str) {
        assert!(error.contains(expected), "unexpected error: {error}");
    }

    #[rstest]
    #[case::valid(1, 0)]
    #[case::invalid(2, 1)]
    #[case::suspended(3, 2)]
    #[case::app_specific(4, 3)]
    #[tokio::test]
    async fn entry_is_read_from_a_trusted_cwt(#[case] idx: usize, #[case] expected: u8) {
        let status = entry(&x5c_status_list_cwt(URI), idx, trusted())
            .await
            .unwrap();

        assert_eq!(status, Some(expected));
    }

    #[rstest]
    #[case::untagged(cwt_with(|spec| spec["tagged"] = json!(false)))]
    #[case::x5chain_unprotected(cwt_with(|spec| spec["x5chain_unprotected"] = json!(true)))]
    #[case::without_exp(cwt_with(|spec| { spec.as_object_mut().unwrap().remove("exp"); }))]
    #[case::float_iat(cwt_with(|spec| spec["iat"] = json!(1790000000.5)))]
    #[case::chain_with_its_root(cwt_with(|spec| {
        spec["x5chain"] = json!(format!("{}{}", status_list_signer_cert(), status_list_root_ca()));
    }))]
    #[tokio::test]
    async fn cwt_variants_are_accepted(#[case] token: Vec<u8>) {
        let status = entry(&token, 2, trusted()).await.unwrap();

        assert_eq!(status, Some(1));
    }

    #[tokio::test]
    async fn cwt_whose_signer_is_held_as_an_anchor_is_accepted() {
        let status = entry(
            &x5c_status_list_cwt(URI),
            2,
            Some(anchors(&[status_list_signer_cert()])),
        )
        .await
        .unwrap();

        assert_eq!(status, Some(1));
    }

    #[tokio::test]
    async fn index_out_of_bounds_reads_no_entry() {
        let status = entry(&x5c_status_list_cwt(URI), 1_000_000, trusted())
            .await
            .unwrap();

        assert_eq!(status, None);
    }

    #[tokio::test]
    async fn cwt_for_another_uri_is_rejected() {
        let error = error_of(
            x5c_status_list_cwt("https://status.example/other"),
            trusted(),
        )
        .await;

        assert_contains(&error, "Urls are not equal");
    }

    #[tokio::test]
    async fn expired_cwt_is_rejected() {
        let error = error_of(cwt_with(|spec| spec["exp"] = json!(1700000000)), trusted()).await;

        assert_contains(&error, "status list CWT has expired");
    }

    #[tokio::test]
    async fn cwt_without_iat_is_rejected() {
        let token = cwt_with(|spec| {
            spec.as_object_mut().unwrap().remove("iat");
        });

        let error = error_of(token, trusted()).await;

        assert_contains(&error, "missed the `iat` claim");
    }

    fn iat_from_now(offset_secs: i64) -> Value {
        json!(time::OffsetDateTime::now_utc().unix_timestamp() + offset_secs)
    }

    #[tokio::test]
    async fn cwt_issued_in_the_future_is_rejected() {
        let token = cwt_with(|spec| spec["iat"] = iat_from_now(3600));

        let error = error_of(token, trusted()).await;

        assert_contains(&error, "status list CWT `iat` is in the future");
    }

    #[tokio::test]
    async fn cwt_issued_slightly_ahead_of_this_clock_is_accepted() {
        let token = cwt_with(|spec| spec["iat"] = iat_from_now(10));

        let status = entry(&token, 2, trusted()).await.unwrap();

        assert_eq!(status, Some(1));
    }

    #[rstest]
    #[case::other_typ(cwt_with(|spec| spec["typ"] = json!("application/cwt")), "expected protected `typ`")]
    #[case::no_typ(cwt_with(|spec| { spec.as_object_mut().unwrap().remove("typ"); }), "expected protected `typ`")]
    #[case::no_x5chain(cwt_with(|spec| { spec.as_object_mut().unwrap().remove("x5chain"); }), "has no `x5chain`")]
    #[case::three_bits(cwt_with(|spec| spec["bits"] = json!(3)), "Malformed status list")]
    #[case::not_cose(b"not a status list".to_vec(), "not a COSE_Sign1")]
    #[tokio::test]
    async fn malformed_cwt_is_rejected(#[case] token: Vec<u8>, #[case] expected: &str) {
        let error = error_of(token, trusted()).await;

        assert_contains(&error, expected);
    }

    #[tokio::test]
    async fn cwt_typed_by_its_coap_content_format_id_is_accepted() {
        let token = cwt_with(|spec| spec["typ"] = json!(279));

        let status = entry(&token, 2, trusted()).await.unwrap();

        assert_eq!(status, Some(1));
    }

    #[rstest]
    #[case::alg(json!([1]))]
    #[case::typ_and_x5chain(json!([16, 33]))]
    #[tokio::test]
    async fn cwt_whose_crit_names_only_checked_parameters_is_accepted(#[case] crit: Value) {
        let token = cwt_with(|spec| spec["crit"] = crit);

        let status = entry(&token, 2, trusted()).await.unwrap();

        assert_eq!(status, Some(1));
    }

    #[rstest]
    #[case::other_coap_id(cwt_with(|spec| spec["typ"] = json!(61)), "expected protected `typ`")]
    #[case::unknown_crit(cwt_with(|spec| spec["crit"] = json!([4])), "protected `crit` names unsupported parameters")]
    #[case::es384(cwt_with(|spec| spec["alg"] = json!(-35)), "unsupported or missing protected `alg`")]
    #[tokio::test]
    async fn cwt_with_an_unsupported_header_is_rejected(
        #[case] token: Vec<u8>,
        #[case] expected: &str,
    ) {
        let error = error_of(token, trusted()).await;

        assert_contains(&error, expected);
    }

    #[tokio::test]
    async fn cwt_whose_alg_does_not_match_its_certificate_key_is_rejected() {
        let token = cwt_with(|spec| spec["alg"] = json!(-8));

        let error = error_of(token, trusted()).await;

        assert_contains(&error, "does not match its certificate's key");
    }

    #[tokio::test]
    async fn cwt_signed_by_a_key_other_than_its_certificate_is_rejected() {
        let token = test_fixtures::status_list_cwt(&spec(URI), &test_fixtures::keys().holder);

        let error = error_of(token, trusted()).await;

        assert_contains(&error, "status list signature is invalid");
    }

    #[rstest]
    #[case::no_trusted_anchors(None)]
    #[case::unrelated_anchor(Some(anchors(&[unrelated_root_ca().as_str()])))]
    #[tokio::test]
    async fn cwt_without_its_anchor_is_rejected(
        #[case] trusted_certs: Option<HashMap<String, String>>,
    ) {
        let error = error_of(x5c_status_list_cwt(URI), trusted_certs).await;

        assert_contains(&error, "Certificate chain is not trusted");
    }

    fn unrelated_root_ca() -> String {
        test_fixtures::x509(
            &json!({
                "subject": [["CN", "Unrelated CWT Root CA"]],
                "not_before": "2025-01-01", "not_after": "2046-01-01",
                "ca": true, "key_usages": ["key_cert_sign", "crl_sign"]
            }),
            &test_fixtures::JWK::generate_p256(),
            None,
        )
    }
}
