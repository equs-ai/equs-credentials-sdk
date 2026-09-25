//! Bundle-level checks: every contract key is present, and no token in the
//! bundle is already expired.
//!
//! Run with `--features delegate-sd-jwt` (or `--all-features`) — without it,
//! [`test_fixtures::bundle::build`] fails on purpose (see its docs), so this
//! whole suite is gated the same way `tests/delegation.rs` is.

#![cfg(feature = "delegate-sd-jwt")]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

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

#[tokio::test]
async fn bundle_contains_every_wrapper_fixture() -> test_fixtures::Result<()> {
    let bundle = test_fixtures::bundle::build().await?;

    for name in [
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
    ] {
        assert!(bundle.get(name).is_some(), "bundle is missing {name}");
    }
    assert_eq!(
        bundle.len(),
        10,
        "unexpected number of fixtures: {bundle:?}"
    );
    Ok(())
}

#[tokio::test]
async fn bundle_holds_no_expired_token() -> test_fixtures::Result<()> {
    let bundle = test_fixtures::bundle::build().await?;
    for (name, value) in bundle.tokens() {
        if let Some(exp) = exp_of(value) {
            assert!(
                exp > test_fixtures::claims::now(),
                "{name} is already expired"
            );
        }
    }
    Ok(())
}
