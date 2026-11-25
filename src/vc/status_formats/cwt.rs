//! Verifies the CWTs that mdoc revocation lists come in (draft-ietf-oauth-status-list §5.2,
//! ISO/IEC 18013-5 2nd ed.).
//!
//! A token is accepted only when:
//! - it is a COSE_Sign1, tagged or untagged, with nothing after it;
//! - its `x5chain` certificate chain is trusted under the caller's [AnchorPolicy];
//! - its signature verifies with the key of the first certificate in that chain;
//! - its protected `typ` is the list's media type, or its CoAP ID where it has one;
//! - its `alg` is ES256 with a P-256 key or EdDSA with an Ed25519 key;
//! - its protected `crit` lists only `alg`, `typ` and `x5chain`;
//! - its claims are one CBOR map, with nothing after it;
//! - its `sub` is the URI it was fetched from;
//! - its `iat` is at most 60 seconds ahead, and it has not expired; `exp` is optional.
//!
//! `ttl` is ignored, since the cache lasts for one call only.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use coset::cbor::value::Value;
use coset::iana::{Algorithm, EnumI64};
use coset::{
    Algorithm as CoseAlgorithm, CborSerializable, CoseSign1, Header, Label,
    RegisteredLabelWithPrivate, TaggedCborSerializable,
};
use oauth2::http;
use oauth2::http::Method;
use one_core_portable::standardized_types::jwk::PublicJwk;

use crate::http::HttpClient;
use crate::utils::certificate_validator::SharedCertificateValidator;
use crate::utils::x509_truststore::Truststore;
use crate::vc::formats::AnchorPolicy;
use crate::vc::status_formats::{
    MalformedStatusListSnafu, Result, StatusListFetchingSnafu, VCStatusSnafu,
};

const ALG_HEADER: i64 = 1;
const TYP_HEADER: i64 = 16;
const X5CHAIN_HEADER: i64 = 33;
const SUB_CLAIM: i64 = 2;
const EXP_CLAIM: i64 = 4;
const IAT_CLAIM: i64 = 6;

/// How far `iat` may be ahead of this clock, for clock skew with the list's issuer.
const MAX_IAT_SKEW_SECS: f64 = 60.0;

/// Largest list body accepted from a server.
pub(crate) const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// The kind of list a CWT carries.
pub(crate) struct CwtProfile {
    /// Name used in error messages.
    pub(crate) name: &'static str,
    /// Media type, also accepted as the `typ` header.
    pub(crate) media_type: &'static str,
    /// CoAP ID of the media type, also accepted as the `typ` header.
    pub(crate) coap_id: Option<i64>,
}

/// CWT claims, keyed as in the token.
pub(crate) type Claims = Vec<(Value, Value)>;

/// Fetches the `profile` list at `uri`: asks for the profile's media type only, and requires a
/// success status, a `Content-Type` whose media type (before any `;` parameters, any case) is the
/// profile's, and a body of at most [MAX_BODY_BYTES]. The cap applies once the [HttpClient] has
/// returned the whole body, so it bounds what is parsed, not what is downloaded.
pub(crate) async fn fetch(
    http_client: &dyn HttpClient,
    uri: &str,
    profile: &CwtProfile,
) -> Result<Vec<u8>> {
    let fetching = |details: String| StatusListFetchingSnafu { details }.build();
    let request = http::request::Builder::new()
        .uri(uri)
        .method(Method::GET)
        .header(http::header::ACCEPT, profile.media_type)
        .body(vec![])
        .map_err(|err| fetching(err.to_string()))?;
    let response = http_client
        .async_call(request)
        .await
        .map_err(|err| fetching(err.to_string()))?;
    if !response.status().is_success() {
        return Err(fetching(format!(
            "{} request failed with {}",
            profile.name,
            response.status()
        )));
    }
    let has_media_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case(profile.media_type));
    if !has_media_type {
        return Err(fetching(format!(
            "{} is not served as {}",
            profile.name, profile.media_type
        )));
    }
    let body = response.into_body();
    if body.len() > MAX_BODY_BYTES {
        return Err(fetching(format!(
            "{} is larger than {MAX_BODY_BYTES} bytes",
            profile.name
        )));
    }
    Ok(body)
}

/// Verifies the CWT `token` fetched from `uri` and returns its claims.
pub(crate) async fn verify(
    profile: &CwtProfile,
    uri: &str,
    token: &[u8],
    trusted_certs: Option<&HashMap<String, String>>,
    anchor_policy: AnchorPolicy,
) -> Result<Claims> {
    let sign1 = decode_sign1(token)?;
    check_crit(&sign1.protected.header)?;
    check_typ(profile, &sign1.protected.header)?;
    let alg = check_alg(&sign1.protected.header)?;

    let pem_chain = x5chain_pem(profile, &sign1)?;
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
    check_key_matches_alg(profile, leaf.public_key.public_key_as_jwk(), alg)?;
    sign1
        .verify_signature(b"", |signature, data| {
            leaf.public_key.verify(data, signature)
        })
        .map_err(|err| {
            VCStatusSnafu {
                details: format!("{} signature is invalid: {err}", profile.name),
            }
            .build()
        })?;

    let claims = decode_claims(profile, &sign1)?;
    check_sub(&claims, uri)?;
    check_times(profile, &claims)?;
    Ok(claims)
}

pub(crate) fn malformed(details: impl Into<String>) -> crate::vc::status_formats::Error {
    MalformedStatusListSnafu {
        details: details.into(),
    }
    .build()
}

pub(crate) fn claim(claims: &[(Value, Value)], key: i64) -> Option<&Value> {
    claims
        .iter()
        .find(|(name, _)| name.as_integer() == Some(key.into()))
        .map(|(_, value)| value)
}

fn decode_sign1(token: &[u8]) -> Result<CoseSign1> {
    CoseSign1::from_tagged_slice(token)
        .or_else(|_| CoseSign1::from_slice(token))
        .map_err(|err| malformed(format!("not a COSE_Sign1: {err}")))
}

fn header_param(header: &Header, label: i64) -> Option<&Value> {
    header
        .rest
        .iter()
        .find(|(key, _)| *key == Label::Int(label))
        .map(|(_, value)| value)
}

/// Rejects the token when `crit` names a header this code does not check.
fn check_crit(protected: &Header) -> Result<()> {
    let unknown: Vec<_> = protected
        .crit
        .iter()
        .filter(|label| {
            !matches!(
                label,
                RegisteredLabelWithPrivate::Assigned(param)
                    if [ALG_HEADER, TYP_HEADER, X5CHAIN_HEADER].contains(&param.to_i64())
            )
        })
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(malformed(format!(
        "protected `crit` names unsupported parameters: {unknown:?}"
    )))
}

fn check_typ(profile: &CwtProfile, protected: &Header) -> Result<()> {
    let typ = header_param(protected, TYP_HEADER);
    let known = match typ {
        Some(Value::Text(text)) => text == profile.media_type,
        Some(Value::Integer(id)) => profile
            .coap_id
            .is_some_and(|coap_id| i128::from(*id) == i128::from(coap_id)),
        _ => false,
    };
    if known {
        return Ok(());
    }
    Err(malformed(format!(
        "expected protected `typ` {}, got {typ:?}",
        profile.media_type
    )))
}

fn check_alg(protected: &Header) -> Result<Algorithm> {
    match &protected.alg {
        Some(CoseAlgorithm::Assigned(alg @ (Algorithm::ES256 | Algorithm::EdDSA))) => Ok(*alg),
        other => Err(malformed(format!(
            "unsupported or missing protected `alg` (ES256 or EdDSA): {other:?}"
        ))),
    }
}

/// Checks that `alg` fits the certificate key, since one-core picks the algorithm from the key.
fn check_key_matches_alg<E: std::fmt::Display>(
    profile: &CwtProfile,
    key: core::result::Result<PublicJwk, E>,
    alg: Algorithm,
) -> Result<()> {
    let key = key.map_err(|err| {
        VCStatusSnafu {
            details: format!(
                "could not read the {} certificate's key: {err}",
                profile.name
            ),
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
        details: format!(
            "{} CWT `alg` {alg:?} does not match its certificate's key",
            profile.name
        ),
    }
    .fail()
}

/// Returns the `x5chain` certificates as a PEM chain, signer first.
fn x5chain_pem(profile: &CwtProfile, sign1: &CoseSign1) -> Result<String> {
    let x5chain = header_param(&sign1.protected.header, X5CHAIN_HEADER)
        .or_else(|| header_param(&sign1.unprotected, X5CHAIN_HEADER))
        .ok_or_else(|| {
            VCStatusSnafu {
                details: format!(
                    "{} CWT has no `x5chain` to resolve its signing key",
                    profile.name
                ),
            }
            .build()
        })?;
    let certificates = match x5chain {
        Value::Bytes(der) => vec![der],
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_bytes())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| malformed("`x5chain` must hold DER certificates"))?,
        _ => return Err(malformed("`x5chain` must hold DER certificates")),
    };
    if certificates.is_empty() {
        return Err(malformed("`x5chain` is empty"));
    }
    let x5c: Vec<String> = certificates
        .into_iter()
        .map(|der| STANDARD.encode(der))
        .collect();
    one_core::mapper::x509::x5c_into_pem_chain(&x5c)
        .map_err(|err| malformed(format!("could not read `x5chain`: {err}")))
}

fn decode_claims(profile: &CwtProfile, sign1: &CoseSign1) -> Result<Claims> {
    let payload = sign1
        .payload
        .as_deref()
        .ok_or_else(|| malformed(format!("{} CWT has no payload", profile.name)))?;
    let mut reader = std::io::Cursor::new(payload);
    let claims: Value = coset::cbor::de::from_reader(&mut reader)
        .map_err(|err| malformed(format!("{} CWT claims are not CBOR: {err}", profile.name)))?;
    if reader.position() != payload.len() as u64 {
        return Err(malformed(format!(
            "{} CWT claims are followed by extra bytes",
            profile.name
        )));
    }
    match claims {
        Value::Map(entries) => Ok(entries),
        _ => Err(malformed(format!(
            "{} CWT claims are not a map",
            profile.name
        ))),
    }
}

fn check_sub(claims: &[(Value, Value)], uri: &str) -> Result<()> {
    let sub = claim(claims, SUB_CLAIM)
        .ok_or_else(|| malformed("missed the `sub` claim"))?
        .as_text()
        .ok_or_else(|| malformed("the `sub` claim must be a URI"))?;
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

fn check_times(profile: &CwtProfile, claims: &[(Value, Value)]) -> Result<()> {
    let iat = claim(claims, IAT_CLAIM)
        .ok_or_else(|| malformed("missed the `iat` claim"))
        .and_then(|iat| numeric_date(iat).ok_or_else(|| malformed("`iat` is not a NumericDate")))?;
    let now = (time::OffsetDateTime::now_utc() - time::OffsetDateTime::UNIX_EPOCH).as_seconds_f64();
    if iat > now + MAX_IAT_SKEW_SECS {
        return VCStatusSnafu {
            details: format!("{} CWT `iat` is in the future", profile.name),
        }
        .fail();
    }

    let Some(exp) = claim(claims, EXP_CLAIM) else {
        return Ok(());
    };
    let exp = numeric_date(exp).ok_or_else(|| malformed("`exp` is not a NumericDate"))?;
    if exp <= now {
        return VCStatusSnafu {
            details: format!("{} CWT has expired", profile.name),
        }
        .fail();
    }
    Ok(())
}
