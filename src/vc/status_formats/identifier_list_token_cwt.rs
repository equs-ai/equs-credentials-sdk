//! Reads Identifier Lists (ISO/IEC 18013-5 2nd ed.), the revocation list an mdoc names in its
//! MSO `status.identifier_list`. A credential whose identifier is in the list is revoked.
//!
//! The token checks are in [crate::vc::status_formats::cwt]. On top of them, a list is accepted
//! only when it has no `status_list` claim and its `identifiers` are byte strings.

use coset::cbor::value::Value;
use snafu::ensure;
use tracing::{Level, instrument};

use crate::http::HttpClient;
use crate::vc::status_formats::cwt::{self, CwtProfile, claim};
use crate::vc::status_formats::list_trust::ListTrust;
use crate::vc::status_formats::{MalformedStatusListSnafu, Result};

/// Media type and `typ` header of an Identifier List.
pub(crate) const IDENTIFIER_LIST_CWT_TYPE: &str = "application/identifierlist+cwt";

const IDENTIFIER_LIST_CLAIM: i64 = 65530;
const STATUS_LIST_CLAIM: i64 = 65533;

const MAX_IDENTIFIERS: usize = 1_000_000;

const PROFILE: CwtProfile = CwtProfile {
    name: "identifier list",
    media_type: IDENTIFIER_LIST_CWT_TYPE,
    coap_id: None,
};

pub(crate) struct IdentifierListCwt;

impl IdentifierListCwt {
    /// Fetches the Identifier List at `uri` and returns whether `id` is in it.
    #[instrument(level = Level::TRACE, skip(http_client, id, trust), err())]
    pub(crate) async fn is_revoked(
        http_client: &dyn HttpClient,
        uri: &str,
        id: &[u8],
        trust: &ListTrust,
    ) -> Result<bool> {
        let token = cwt::fetch(http_client, uri, &PROFILE).await?;
        Self::is_listed(uri, &token, id, trust).await
    }

    /// Verifies the CWT `token` fetched from `uri` and returns whether `id` is in it.
    #[instrument(level = Level::TRACE, skip(token, id, trust), err())]
    pub(crate) async fn is_listed(
        uri: &str,
        token: &[u8],
        id: &[u8],
        trust: &ListTrust,
    ) -> Result<bool> {
        let claims = cwt::verify(&PROFILE, uri, token, trust).await?;
        ensure!(
            claim(&claims, STATUS_LIST_CLAIM).is_none(),
            MalformedStatusListSnafu {
                details: "identifier list CWT has a `status_list` claim",
            }
        );
        let identifiers = identifiers(&claims)?;
        Ok(identifiers
            .iter()
            .any(|(identifier, _)| identifier.as_bytes().is_some_and(|bytes| bytes == id)))
    }
}

/// The `identifiers` map of the identifier list claim.
fn identifiers(claims: &[(Value, Value)]) -> Result<&[(Value, Value)]> {
    let Some(Value::Map(list)) = claim(claims, IDENTIFIER_LIST_CLAIM) else {
        return MalformedStatusListSnafu {
            details: "missed the identifier list claim",
        }
        .fail();
    };
    let identifiers = list
        .iter()
        .find(|(key, _)| key.as_text() == Some("identifiers"))
        .map(|(_, value)| value);
    let Some(Value::Map(identifiers)) = identifiers else {
        return MalformedStatusListSnafu {
            details: "the identifier list has no `identifiers` map",
        }
        .fail();
    };
    ensure!(
        identifiers.len() <= MAX_IDENTIFIERS,
        MalformedStatusListSnafu {
            details: format!("the identifier list has more than {MAX_IDENTIFIERS} identifiers"),
        }
    );
    ensure!(
        identifiers
            .iter()
            .all(|(identifier, _)| identifier.is_bytes()),
        MalformedStatusListSnafu {
            details: "identifiers must be byte strings",
        }
    );
    Ok(identifiers)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{IDENTIFIER_LIST_CLAIM, IdentifierListCwt, MAX_IDENTIFIERS, identifiers};
    use crate::http::{HttpResponse, MockHttpClient};
    use crate::utils::http::test::mock_http_fn;
    use crate::utils::test_utils::anchors;
    use crate::vc::formats::AnchorPolicy;
    use crate::vc::status_formats::cwt::MAX_BODY_BYTES;
    use crate::vc::status_formats::list_trust::ListTrust;
    use crate::vc::status_formats::status_list_token_jwt::tests::{
        status_list_root_ca, status_list_signer_cert,
    };
    use coset::cbor::value::Value as Cbor;
    use oauth2::http::Method;
    use oauth2::http::StatusCode;
    use oauth2::http::header::{ACCEPT, CONTENT_TYPE};
    use rstest::rstest;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::str::FromStr;
    use url::Url;

    const URI: &str = "https://status.example/identifiers/1";

    /// `6482` in base64url, listed in [identifier_list_cwt].
    pub(crate) const LISTED_ID: &str = "NjQ4Mg";
    const LISTED: &[u8] = b"6482";
    const NOT_LISTED: &[u8] = &[1, 2, 3];

    fn spec(sub: &str) -> Value {
        json!({
            "sub": sub,
            "iat": 1790000000,
            "exp": 2200000000i64,
            "identifiers": [LISTED_ID, "_w"],
            "typ": "application/identifierlist+cwt",
            "x5chain": status_list_signer_cert(),
        })
    }

    /// An Identifier List for `sub` listing [LISTED_ID], signed under [status_list_root_ca].
    pub(crate) fn identifier_list_cwt(sub: &str) -> Vec<u8> {
        test_fixtures::status_list_cwt(&spec(sub), &test_fixtures::keys().issuer)
    }

    /// An Identifier List for `sub` listing [LISTED_ID], signed by `key` under `x5chain`.
    pub(crate) fn identifier_list_cwt_signed_by(
        sub: &str,
        x5chain: &str,
        key: &test_fixtures::JWK,
    ) -> Vec<u8> {
        let mut spec = spec(sub);
        spec["x5chain"] = json!(x5chain);
        test_fixtures::status_list_cwt(&spec, key)
    }

    fn cwt_with(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut spec = spec(URI);
        edit(&mut spec);
        test_fixtures::status_list_cwt(&spec, &test_fixtures::keys().issuer)
    }

    fn trusted() -> Option<HashMap<String, String>> {
        Some(anchors(&[status_list_root_ca()]))
    }

    fn any_of(trusted_certs: Option<HashMap<String, String>>) -> ListTrust {
        ListTrust::AnyOf {
            anchors: trusted_certs.unwrap_or_default(),
            policy: AnchorPolicy::Require,
        }
    }

    async fn listed(token: &[u8], id: &[u8]) -> crate::vc::status_formats::Result<bool> {
        IdentifierListCwt::is_listed(URI, token, id, &any_of(trusted())).await
    }

    async fn error_of(token: Vec<u8>) -> String {
        listed(&token, LISTED).await.unwrap_err().to_string()
    }

    fn assert_contains(error: &str, expected: &str) {
        assert!(error.contains(expected), "unexpected error: {error}");
    }

    #[rstest]
    #[case::listed(LISTED, true)]
    #[case::not_listed(NOT_LISTED, false)]
    #[tokio::test]
    async fn identifier_is_looked_up_in_a_trusted_list(#[case] id: &[u8], #[case] expected: bool) {
        assert_eq!(
            listed(&identifier_list_cwt(URI), id).await.unwrap(),
            expected
        );
    }

    #[rstest]
    #[case::untagged(cwt_with(|spec| spec["tagged"] = json!(false)))]
    #[case::without_exp(cwt_with(|spec| { spec.as_object_mut().unwrap().remove("exp"); }))]
    #[case::x5chain_unprotected(cwt_with(|spec| spec["x5chain_unprotected"] = json!(true)))]
    #[tokio::test]
    async fn list_variants_are_accepted(#[case] token: Vec<u8>) {
        assert!(listed(&token, LISTED).await.unwrap());
    }

    #[tokio::test]
    async fn empty_list_lists_nothing() {
        let token = cwt_with(|spec| spec["identifiers"] = json!([]));

        assert!(!listed(&token, LISTED).await.unwrap());
    }

    #[rstest]
    #[case::status_list_typ(
        cwt_with(|spec| spec["typ"] = json!("application/statuslist+cwt")),
        "expected protected `typ` application/identifierlist+cwt"
    )]
    #[case::status_list_coap_id(cwt_with(|spec| spec["typ"] = json!(279)), "expected protected `typ`")]
    #[case::status_list_claim(
        cwt_with(|spec| { spec["bits"] = json!(1); spec["lst"] = json!("eNoDAAAAAAE"); }),
        "identifier list CWT has a `status_list` claim"
    )]
    #[case::other_uri(
        identifier_list_cwt("https://status.example/other"),
        "Urls are not equal"
    )]
    #[case::expired(cwt_with(|spec| spec["exp"] = json!(1700000000)), "identifier list CWT has expired")]
    #[case::issued_in_the_future(
        cwt_with(|spec| spec["iat"] = json!(time::OffsetDateTime::now_utc().unix_timestamp() + 3600)),
        "identifier list CWT `iat` is in the future"
    )]
    #[case::other_signer(
        test_fixtures::status_list_cwt(&spec(URI), &test_fixtures::keys().holder),
        "identifier list signature is invalid"
    )]
    #[case::trailing_bytes(
        [identifier_list_cwt(URI), vec![0x3f, 0xd5, 0x45, 0x09, 0x48, 0xbc]].concat(),
        "not a COSE_Sign1"
    )]
    #[case::signed_trailing_bytes(
        cwt_with(|spec| spec["payload_suffix"] = json!("P9VF")),
        "identifier list CWT claims are followed by extra bytes"
    )]
    #[tokio::test]
    async fn list_failing_a_token_check_is_rejected(
        #[case] token: Vec<u8>,
        #[case] expected: &str,
    ) {
        assert_contains(&error_of(token).await, expected);
    }

    #[rstest]
    #[case::not_a_map(json!("6482"), "missed the identifier list claim")]
    #[case::no_identifiers(json!({}), "has no `identifiers` map")]
    #[case::identifiers_not_a_map(json!({ "identifiers": "6482" }), "has no `identifiers` map")]
    #[case::text_identifier(json!({ "identifiers": { "6482": {} } }), "identifiers must be byte strings")]
    #[tokio::test]
    async fn malformed_identifier_list_claim_is_rejected(
        #[case] identifier_list: Value,
        #[case] expected: &str,
    ) {
        let token = cwt_with(|spec| {
            spec.as_object_mut().unwrap().remove("identifiers");
            spec["identifier_list"] = identifier_list;
        });

        assert_contains(&error_of(token).await, expected);
    }

    fn claims_with_identifiers(count: usize) -> Vec<(Cbor, Cbor)> {
        let identifiers = (0..count as u32)
            .map(|i| (Cbor::Bytes(i.to_be_bytes().to_vec()), Cbor::Map(Vec::new())))
            .collect();
        vec![(
            Cbor::Integer(IDENTIFIER_LIST_CLAIM.into()),
            Cbor::Map(vec![(
                Cbor::Text("identifiers".to_string()),
                Cbor::Map(identifiers),
            )]),
        )]
    }

    #[test]
    fn list_at_the_identifier_cap_is_read() {
        let claims = claims_with_identifiers(MAX_IDENTIFIERS);

        assert_eq!(identifiers(&claims).unwrap().len(), MAX_IDENTIFIERS);
    }

    #[test]
    fn list_over_the_identifier_cap_is_rejected() {
        let claims = claims_with_identifiers(MAX_IDENTIFIERS + 1);

        let error = identifiers(&claims).unwrap_err().to_string();

        assert_contains(&error, "more than 1000000 identifiers");
    }

    #[tokio::test]
    async fn list_without_its_anchor_is_rejected() {
        let error =
            IdentifierListCwt::is_listed(URI, &identifier_list_cwt(URI), LISTED, &any_of(None))
                .await
                .unwrap_err()
                .to_string();

        assert_contains(&error, "Certificate chain is not trusted");
    }

    fn only(anchor: &str) -> ListTrust {
        ListTrust::Anchor {
            ski: "anchor".to_string(),
            pem: anchor.to_string(),
        }
    }

    #[tokio::test]
    async fn list_under_its_only_anchor_is_read() {
        let listed = IdentifierListCwt::is_listed(
            URI,
            &identifier_list_cwt(URI),
            LISTED,
            &only(status_list_root_ca()),
        )
        .await
        .unwrap();

        assert!(listed);
    }

    #[tokio::test]
    async fn list_under_another_trusted_anchor_is_rejected() {
        let other_root = test_fixtures::x509(
            &json!({
                "subject": [["CN", "Other Identifier List Root"]],
                "not_before": "2025-01-01", "not_after": "2046-01-01",
                "ca": true, "key_usages": ["key_cert_sign", "crl_sign"]
            }),
            &test_fixtures::JWK::generate_p256(),
            None,
        );

        let error = IdentifierListCwt::is_listed(
            URI,
            &identifier_list_cwt(URI),
            LISTED,
            &only(&other_root),
        )
        .await
        .unwrap_err()
        .to_string();

        assert_contains(&error, "Certificate chain is not trusted");
    }

    #[tokio::test]
    async fn error_does_not_name_the_identifier() {
        let id = b"credential-6482";
        let token = cwt_with(|spec| spec["exp"] = json!(1700000000));

        let error = listed(&token, id).await.unwrap_err().to_string();

        assert!(!error.contains("credential-6482"), "{error}");
        assert!(!error.contains("Y3JlZGVudGlhbC02NDgy"), "{error}");
    }

    fn served(
        body: Vec<u8>,
        content_type: Option<&'static str>,
        status: StatusCode,
    ) -> MockHttpClient {
        let mut http_client = MockHttpClient::new();
        mock_http_fn(
            &mut http_client,
            Method::GET,
            Url::from_str(URI).unwrap(),
            move |request| {
                assert_eq!(request.headers()[ACCEPT], "application/identifierlist+cwt");
                let mut response = HttpResponse::new(body.clone());
                *response.status_mut() = status;
                if let Some(content_type) = content_type {
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, content_type.parse().unwrap());
                }
                Ok(response)
            },
            1.into(),
        );
        http_client
    }

    async fn revoked(http_client: MockHttpClient) -> crate::vc::status_formats::Result<bool> {
        IdentifierListCwt::is_revoked(&http_client, URI, LISTED, &any_of(trusted())).await
    }

    #[rstest]
    #[case::exact("application/identifierlist+cwt")]
    #[case::with_parameters("Application/IdentifierList+CWT; charset=binary")]
    #[tokio::test]
    async fn list_is_fetched_and_read(#[case] content_type: &'static str) {
        let http_client = served(identifier_list_cwt(URI), Some(content_type), StatusCode::OK);

        assert!(revoked(http_client).await.unwrap());
    }

    #[rstest]
    #[case::status_list_type(
        identifier_list_cwt(URI),
        Some("application/statuslist+cwt"),
        StatusCode::OK,
        "is not served as application/identifierlist+cwt"
    )]
    #[case::no_content_type(identifier_list_cwt(URI), None, StatusCode::OK, "is not served as")]
    #[case::longer_media_type(
        identifier_list_cwt(URI),
        Some("application/identifierlist+cwtx"),
        StatusCode::OK,
        "is not served as"
    )]
    #[case::not_found(
        identifier_list_cwt(URI),
        Some("application/identifierlist+cwt"),
        StatusCode::NOT_FOUND,
        "failed with 404"
    )]
    #[case::too_large(
        vec![0; MAX_BODY_BYTES + 1],
        Some("application/identifierlist+cwt"),
        StatusCode::OK,
        "is larger than"
    )]
    #[tokio::test]
    async fn list_that_cannot_be_fetched_is_rejected(
        #[case] body: Vec<u8>,
        #[case] content_type: Option<&'static str>,
        #[case] status: StatusCode,
        #[case] expected: &str,
    ) {
        let error = revoked(served(body, content_type, status))
            .await
            .unwrap_err()
            .to_string();

        assert_contains(&error, expected);
    }
}
