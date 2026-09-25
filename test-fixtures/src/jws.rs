//! Compact JWS assembly on top of the SDK's [`Signer`] trait.
//!
//! Several of the JWT kinds the SDK handles are built inline inside private
//! modules (`vc::pop` is private, `vc::formats` is `pub(crate)`), so there is no
//! public constructor to call. Those kinds are assembled here instead — but the
//! signature still comes from a [`FixtureKey`]'s KMS handle, never from raw key
//! material, so a fixture exercises the same signing path as production code.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use equs_sdk::crypto::Signer;
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::keys::FixtureKey;

/// Signs `claims` into a compact JWS with `typ` in the header.
///
/// The header carries `alg` (taken from the signer), `typ`, and `kid` set to the
/// key's verification method URL — the form every SDK verifier resolves against.
///
/// # Errors
///
/// * [`Error::Json`] — the header or claims could not be serialised.
/// * [`Error::Signing`] — the KMS handle refused to sign.
pub async fn sign_compact(key: &FixtureKey, typ: &str, claims: &Value) -> Result<String> {
    let header = serde_json::json!({
        "alg": key.handle.alg().to_string(),
        "typ": typ,
        "kid": key.did_url.to_string(),
    });
    sign_compact_with_header(key, &header, claims).await
}

/// Signs `claims` under a caller-supplied header.
///
/// Used where a kind needs a header this crate should not guess at — an `alg`
/// override, or a `typ` the verifier matches exactly.
///
/// # Errors
///
/// See [`sign_compact`].
pub async fn sign_compact_with_header(
    key: &FixtureKey,
    header: &Value,
    claims: &Value,
) -> Result<String> {
    let header_json = serde_json::to_vec(header).map_err(|e| Error::Json {
        details: e.to_string(),
    })?;
    let claims_json = serde_json::to_vec(claims).map_err(|e| Error::Json {
        details: e.to_string(),
    })?;

    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json),
        URL_SAFE_NO_PAD.encode(claims_json)
    );

    let signature = key
        .handle
        .sign(signing_input.as_bytes())
        .await
        .map_err(|e| Error::Signing {
            details: e.to_string(),
        })?;

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// Merges `overrides` into `claims`, replacing any key already present.
///
/// This is how every builder applies its per-test overrides on top of its
/// defaults: the default set is built first, then the caller's entries win.
pub(crate) fn merge(claims: &mut Map<String, Value>, overrides: Map<String, Value>) {
    for (key, value) in overrides {
        claims.insert(key, value);
    }
}
