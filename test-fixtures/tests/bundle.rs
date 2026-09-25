//! Bundle-level checks: every contract key is present, no token anywhere in
//! the bundle (including nested inside `vp` and `dsdJwtGrantVpToken`) is
//! already expired, and the status-list/credential pair is mutually
//! coherent.
//!
//! Run with `--features delegate-sd-jwt` (or `--all-features`) — without it,
//! [`test_fixtures::bundle::build`] fails on purpose (see its docs), so this
//! whole suite is gated the same way `tests/delegation.rs` is.

#![cfg(feature = "delegate-sd-jwt")]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use equs_sdk::did::universal::UniversalResolver;
use equs_sdk::vc::claims::Claims;
use equs_sdk::vc::status_formats::API as StatusFormatsAPI;
use equs_sdk::vc::status_formats::status_list_token_jwt::{StatusListJwt, VCStatus};
use serde_json::Value;
use test_fixtures::http::StaticHttpClient;

/// Every contract key `bundle::build()` promises. Shared between the
/// presence check and the expiry walk so the two can't silently drift apart.
const CONTRACT_KEYS: &[&str] = &[
    "authRequestJwt",
    "vc",
    "vp",
    "statusListJwt",
    "vcWithStatus",
    "accessToken",
    "proofJwt",
    "sdJwtCreds",
    "authResponseJwe",
    "dsdJwtGrantVpToken",
];

/// The `exp` claim of `value`, if `value` is a compact JWS/JWT whose payload
/// decodes as JSON and carries one.
///
/// Returns `None` rather than panicking for anything that is not a
/// three-segment compact JWT with a numeric `exp` — in particular a compact
/// JWE (five segments, an opaque encrypted second segment), which this
/// bundle also stores as a plain string.
fn exp_of(value: &Value) -> Option<i64> {
    let token = value.as_str()?;
    let payload_segment = token.split('.').nth(1)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("exp")?.as_i64()
}

/// Walks `value` — recursing through objects and arrays — and asserts every
/// string leaf that parses as a compact JWS with an `exp` claim is not
/// already expired.
///
/// This is what makes the check reach `vp.presentation` and
/// `dsdJwtGrantVpToken["fixture-credential"][0]`, not just the bundle's
/// top-level string entries: `Bundle::tokens()` stays shallow (it is a
/// simple "the bare tokens" view used nowhere else), and this test owns the
/// recursion instead of pushing nested-entry iteration into the crate's
/// public API for a need only this test has.
fn assert_no_expired_token(path: &str, value: &Value) {
    match value {
        Value::String(_) => {
            if let Some(exp) = exp_of(value) {
                assert!(
                    exp > test_fixtures::claims::now(),
                    "{path} is already expired"
                );
            }
        }
        Value::Object(map) => {
            for (key, nested) in map {
                assert_no_expired_token(&format!("{path}.{key}"), nested);
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                assert_no_expired_token(&format!("{path}[{index}]"), nested);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn bundle_contains_every_wrapper_fixture() -> test_fixtures::Result<()> {
    let bundle = test_fixtures::bundle::build().await?;

    for name in CONTRACT_KEYS {
        assert!(bundle.get(name).is_some(), "bundle is missing {name}");
    }
    assert_eq!(
        bundle.len(),
        CONTRACT_KEYS.len(),
        "unexpected number of fixtures: {bundle:?}"
    );
    Ok(())
}

#[tokio::test]
async fn bundle_holds_no_expired_token() -> test_fixtures::Result<()> {
    let bundle = test_fixtures::bundle::build().await?;
    for name in CONTRACT_KEYS {
        let value = bundle
            .get(name)
            .unwrap_or_else(|| panic!("bundle is missing {name}"));
        assert_no_expired_token(name, value);
    }
    Ok(())
}

/// `vcWithStatus`/`statusListJwt` is a fixture pair. A pair that silently
/// points at the wrong index is a real failure mode (it already cost a fix
/// round elsewhere in this branch), so this asserts it against the SDK's own
/// status verifier rather than assuming the pairing from how `bundle::build`
/// happens to wire the indices today.
#[tokio::test]
async fn status_pairs_are_mutually_coherent() -> test_fixtures::Result<()> {
    let bundle = test_fixtures::bundle::build().await?;

    let status_list_jwt = bundle.get("statusListJwt").unwrap().as_str().unwrap();
    let vc_with_status = bundle.get("vcWithStatus").unwrap().as_str().unwrap();

    let vc_with_status_claims = decode_payload(vc_with_status);

    let http =
        StaticHttpClient::new().with_response(status_uri(&vc_with_status_claims), status_list_jwt);

    let valid_claims: Claims = vc_with_status_claims.try_into().unwrap();
    let valid_status =
        StatusListJwt::get_vc_status(&valid_claims, &http, UniversalResolver::default(), None)
            .await
            .expect("vcWithStatus must resolve against statusListJwt");
    assert_eq!(
        valid_status,
        Some(VCStatus::Valid),
        "vcWithStatus must read Valid against statusListJwt"
    );

    Ok(())
}

/// The `status.status_list.uri` a credential's decoded payload points at.
fn status_uri(claims: &Value) -> String {
    claims["status"]["status_list"]["uri"]
        .as_str()
        .expect("credential is missing status.status_list.uri")
        .to_string()
}

/// Decodes the unverified payload of a compact JWS, panicking if `token`
/// isn't shaped like one — used only to read a claim back out of a fixture
/// this test just minted, never to verify anything (the SDK verifier calls
/// above do that).
fn decode_payload(token: &str) -> Value {
    let payload_segment = token
        .split('.')
        .nth(1)
        .unwrap_or_else(|| panic!("not a compact JWS: {token}"));
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .unwrap_or_else(|e| panic!("payload segment is not base64url: {e}"));
    serde_json::from_slice(&payload_bytes)
        .unwrap_or_else(|e| panic!("payload segment is not JSON: {e}"))
}
