//! Reads CWT Status List Tokens (draft-ietf-oauth-status-list §5.2), the status list format
//! used by mdoc credentials.
//!
//! A token is accepted only when:
//! - it is a COSE_Sign1, tagged or untagged;
//! - its `x5chain` certificate chain is trusted under the caller's [AnchorPolicy];
//! - its signature verifies with the key of the first certificate in that chain;
//! - its protected `typ` is `application/statuslist+cwt` or the matching CoAP ID;
//! - its `alg` is ES256 with a P-256 key or EdDSA with an Ed25519 key;
//! - its protected `crit` lists only `alg`, `typ` and `x5chain`;
//! - its `sub` is the URI it was fetched from, it has an `iat`, and it has not expired.
//!
//! `ttl` is ignored, since the cache lasts for one call only.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use coset::cbor::value::Value;
use coset::iana::HeaderParameter;
use coset::iana::{Algorithm, EnumI64};
use coset::{
    Algorithm as CoseAlgorithm, CborSerializable, CoseSign1, Header, Label,
    RegisteredLabelWithPrivate, TaggedCborSerializable,
};
use one_core_portable::standardized_types::jwk::PublicJwk;
use snafu::{OptionExt, ensure};
use ssi::status::token_status_list::BitString;
use tracing::{Level, instrument};

use crate::utils::certificate_validator::SharedCertificateValidator;
use crate::utils::x509_truststore::Truststore;
use crate::vc::formats::AnchorPolicy;
use crate::vc::presentation_exchange::StatusSize;
use crate::vc::status_formats::{MalformedStatusListSnafu, Result, VCStatusSnafu};

/// Media type and `typ` header of a CWT Status List Token.
pub(crate) const STATUS_LIST_CWT_TYPE: &str = "application/statuslist+cwt";

/// CoAP ID of `application/statuslist+cwt`, also accepted as the `typ` header.
const STATUS_LIST_CWT_COAP_ID: i64 = 279;

const ALG_HEADER: i64 = 1;
const TYP_HEADER: i64 = 16;
const X5CHAIN_HEADER: i64 = 33;
const SUB_CLAIM: i64 = 2;
const EXP_CLAIM: i64 = 4;
const IAT_CLAIM: i64 = 6;
const STATUS_LIST_CLAIM: i64 = 65533;

/// Headers this module checks: the only ones `crit` may list.
const UNDERSTOOD_CRIT_HEADERS: [i64; 3] = [ALG_HEADER, TYP_HEADER, X5CHAIN_HEADER];

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
        let sign1 = decode_sign1(token)?;
        check_crit(&sign1.protected.header)?;
        check_typ(&sign1.protected.header)?;
        let alg = read_alg(&sign1.protected.header)?;

        let pem_chain = x5chain_pem(&sign1)?;
        let leaf = Truststore::new(
            SharedCertificateValidator::get(),
            trusted_certs.cloned().unwrap_or_default(),
        )
        .anchor_policy(anchor_policy)
        .verify_chain_trust(&pem_chain, "")
        .await
        .map_err(|err| {
            VCStatusSnafu {
                details: err.to_string(),
            }
            .build()
        })?;
        check_key_matches_alg(leaf.public_key.public_key_as_jwk(), alg)?;
        sign1
            .verify_signature(b"", |signature, data| {
                leaf.public_key.verify(data, signature)
            })
            .map_err(|err| {
                VCStatusSnafu {
                    details: format!("status list signature is invalid: {err}"),
                }
                .build()
            })?;

        let claims = decode_claims(&sign1)?;
        check_sub(&claims, uri)?;
        check_times(&claims)?;
        status_list(&claims)
    }
}

fn decode_sign1(token: &[u8]) -> Result<CoseSign1> {
    CoseSign1::from_tagged_slice(token)
        .or_else(|_| CoseSign1::from_slice(token))
        .map_err(|err| {
            MalformedStatusListSnafu {
                details: format!("not a COSE_Sign1: {err}"),
            }
            .build()
        })
}

fn header_param(header: &Header, label: i64) -> Option<&Value> {
    header
        .rest
        .iter()
        .find(|(key, _)| *key == Label::Int(label))
        .map(|(_, value)| value)
}

/// Rejects the token when `crit` names a header this code does not check (RFC 9052 §3.1).
fn check_crit(header: &Header) -> Result<()> {
    let is_understood = |label: &&RegisteredLabelWithPrivate<HeaderParameter>| match label {
        RegisteredLabelWithPrivate::Assigned(param) => {
            UNDERSTOOD_CRIT_HEADERS.contains(&param.to_i64())
        }
        _ => false,
    };
    let unknown: Vec<_> = header
        .crit
        .iter()
        .filter(|label| !is_understood(label))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    MalformedStatusListSnafu {
        details: format!("protected `crit` names unsupported parameters: {unknown:?}"),
    }
    .fail()
}

fn check_typ(protected: &Header) -> Result<()> {
    let typ = header_param(protected, TYP_HEADER);
    let known = match typ {
        Some(Value::Text(text)) => text == STATUS_LIST_CWT_TYPE,
        Some(Value::Integer(id)) => *id == STATUS_LIST_CWT_COAP_ID.into(),
        _ => false,
    };
    if known {
        return Ok(());
    }
    MalformedStatusListSnafu {
        details: format!("expected protected `typ` {STATUS_LIST_CWT_TYPE}, got {typ:?}"),
    }
    .fail()
}

fn read_alg(protected: &Header) -> Result<Algorithm> {
    match &protected.alg {
        Some(CoseAlgorithm::Assigned(alg @ (Algorithm::ES256 | Algorithm::EdDSA))) => Ok(*alg),
        other => MalformedStatusListSnafu {
            details: format!("unsupported or missing protected `alg` (ES256 or EdDSA): {other:?}"),
        }
        .fail(),
    }
}

/// Checks that `alg` fits the certificate key, since one-core picks the algorithm from the key.
fn check_key_matches_alg<E: std::fmt::Display>(
    key: core::result::Result<PublicJwk, E>,
    alg: Algorithm,
) -> Result<()> {
    let key = key.map_err(|err| {
        VCStatusSnafu {
            details: format!("could not read the status list certificate's key: {err}"),
        }
        .build()
    })?;
    let matches = match (&key, alg) {
        (PublicJwk::Ec(ec), Algorithm::ES256) => ec.crv == "P-256",
        (PublicJwk::Okp(okp), Algorithm::EdDSA) => okp.crv == "Ed25519",
        _ => false,
    };
    if matches {
        return Ok(());
    }
    VCStatusSnafu {
        details: format!("status list CWT `alg` {alg:?} does not match its certificate's key"),
    }
    .fail()
}

/// Returns the `x5chain` certificates as a PEM chain, signer first.
fn x5chain_pem(sign1: &CoseSign1) -> Result<String> {
    let x5chain = header_param(&sign1.protected.header, X5CHAIN_HEADER)
        .or_else(|| header_param(&sign1.unprotected, X5CHAIN_HEADER))
        .ok_or_else(|| {
            VCStatusSnafu {
                details: "status list CWT has no `x5chain` to resolve its signing key",
            }
            .build()
        })?;
    let certificates = match x5chain {
        Value::Bytes(der) => vec![der],
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_bytes())
            .collect::<Option<Vec<_>>>()
            .context(MalformedStatusListSnafu {
                details: "`x5chain` must hold DER certificates",
            })?,
        _ => {
            return MalformedStatusListSnafu {
                details: "`x5chain` must hold DER certificates",
            }
            .fail();
        }
    };
    ensure!(
        !certificates.is_empty(),
        MalformedStatusListSnafu {
            details: "`x5chain` is empty",
        }
    );
    let x5c: Vec<String> = certificates
        .into_iter()
        .map(|der| STANDARD.encode(der))
        .collect();
    one_core::mapper::x509::x5c_into_pem_chain(&x5c).map_err(|err| {
        MalformedStatusListSnafu {
            details: format!("could not read `x5chain`: {err}"),
        }
        .build()
    })
}

fn decode_claims(sign1: &CoseSign1) -> Result<Vec<(Value, Value)>> {
    let payload = sign1.payload.as_deref().context(MalformedStatusListSnafu {
        details: "status list CWT has no payload",
    })?;
    let claims: Value = coset::cbor::de::from_reader(payload).map_err(|err| {
        MalformedStatusListSnafu {
            details: format!("status list CWT claims are not CBOR: {err}"),
        }
        .build()
    })?;
    match claims {
        Value::Map(entries) => Ok(entries),
        _ => MalformedStatusListSnafu {
            details: "status list CWT claims are not a map",
        }
        .fail(),
    }
}

fn claim(claims: &[(Value, Value)], key: i64) -> Option<&Value> {
    claims
        .iter()
        .find(|(name, _)| name.as_integer() == Some(key.into()))
        .map(|(_, value)| value)
}

fn check_sub(claims: &[(Value, Value)], uri: &str) -> Result<()> {
    let sub = claim(claims, SUB_CLAIM)
        .context(MalformedStatusListSnafu {
            details: "missed the `sub` claim",
        })?
        .as_text()
        .context(MalformedStatusListSnafu {
            details: "the `sub` claim must be a URI",
        })?;
    if sub != uri {
        return VCStatusSnafu {
            details: format!("Urls are not equal {uri} {sub}"),
        }
        .fail();
    }
    Ok(())
}

/// Reads a NumericDate: whole or fractional seconds since the epoch.
fn numeric_date(value: &Value) -> Option<f64> {
    match value {
        Value::Integer(integer) => Some(i128::from(*integer) as f64),
        Value::Float(float) => Some(*float),
        _ => None,
    }
}

fn check_times(claims: &[(Value, Value)]) -> Result<()> {
    let iat = claim(claims, IAT_CLAIM).context(MalformedStatusListSnafu {
        details: "missed the `iat` claim",
    })?;
    numeric_date(iat).context(MalformedStatusListSnafu {
        details: "`iat` is not a NumericDate",
    })?;

    let Some(exp) = claim(claims, EXP_CLAIM) else {
        return Ok(());
    };
    let exp = numeric_date(exp).context(MalformedStatusListSnafu {
        details: "`exp` is not a NumericDate",
    })?;
    let now = (time::OffsetDateTime::now_utc() - time::OffsetDateTime::UNIX_EPOCH).as_seconds_f64();
    if exp <= now {
        return VCStatusSnafu {
            details: "status list CWT has expired",
        }
        .fail();
    }
    Ok(())
}

fn status_list(claims: &[(Value, Value)]) -> Result<BitString> {
    let Some(Value::Map(status_list)) = claim(claims, STATUS_LIST_CLAIM) else {
        return MalformedStatusListSnafu {
            details: "missed the `status_list` claim",
        }
        .fail();
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
        .context(MalformedStatusListSnafu {
            details: "`status_list.bits` must be 1, 2, 4 or 8",
        })?;
    let bits = StatusSize::try_from(bits).map_err(|err| {
        MalformedStatusListSnafu {
            details: err.to_string(),
        }
        .build()
    })?;
    let lst = field("lst")
        .and_then(Value::as_bytes)
        .context(MalformedStatusListSnafu {
            details: "`status_list.lst` must be a byte string",
        })?;

    BitString::from_compressed_bytes(bits, lst, None).map_err(|err| {
        MalformedStatusListSnafu {
            details: err.to_string(),
        }
        .build()
    })
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
