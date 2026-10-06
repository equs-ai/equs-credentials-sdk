//! Test-only bindings over `equs-test-fixtures` for the JS test suites.

use napi_derive::napi;
use serde_json::Value;
use test_fixtures::JWK;

#[napi]
pub enum FixtureKey {
    Authz,
    Issuer,
    Holder,
    Verifier,
    Secret,
}

impl FixtureKey {
    fn jwk(self) -> &'static JWK {
        let keys = test_fixtures::keys();
        match self {
            FixtureKey::Authz => &keys.authz,
            FixtureKey::Issuer => &keys.issuer,
            FixtureKey::Holder => &keys.holder,
            FixtureKey::Verifier => &keys.verifier,
            FixtureKey::Secret => &keys.secret,
        }
    }
}

fn json(name: &str, text: &str) -> napi::Result<Value> {
    serde_json::from_str(text)
        .map_err(|err| napi::Error::from_reason(format!("`{name}` is not JSON: {err}")))
}

#[napi(catch_unwind)]
pub fn fixture_public_jwk(role: FixtureKey) -> napi::Result<String> {
    serde_json::to_string(&role.jwk().to_public())
        .map_err(|err| napi::Error::from_reason(err.to_string()))
}

#[napi(catch_unwind)]
pub fn fixture_did_key(role: FixtureKey) -> String {
    test_fixtures::did_key(role.jwk())
}

#[napi(catch_unwind)]
pub fn fixture_did_key_url(role: FixtureKey) -> String {
    test_fixtures::did_key_url(role.jwk())
}

#[napi(catch_unwind)]
pub fn fixture_jws(
    header_json: String,
    payload_json: String,
    role: FixtureKey,
) -> napi::Result<String> {
    Ok(test_fixtures::jws(
        &json("header", &header_json)?,
        &json("payload", &payload_json)?,
        role.jwk(),
    ))
}

/// `disclosures` are JSON array texts, digested as given.
#[napi(catch_unwind)]
pub fn fixture_sd_jwt(
    header_json: String,
    claims_json: String,
    disclosures: Vec<String>,
    role: FixtureKey,
) -> napi::Result<String> {
    let disclosures: Vec<&str> = disclosures.iter().map(String::as_str).collect();
    Ok(test_fixtures::sd_jwt(
        &json("header", &header_json)?,
        &json("claims", &claims_json)?,
        &disclosures,
        role.jwk(),
    ))
}

#[napi(catch_unwind)]
pub fn fixture_sd_jwt_kb(
    sd_jwt: String,
    header_json: String,
    claims_json: String,
    role: FixtureKey,
) -> napi::Result<String> {
    Ok(test_fixtures::sd_jwt_kb(
        &sd_jwt,
        &json("header", &header_json)?,
        &json("claims", &claims_json)?,
        role.jwk(),
    ))
}

#[napi(catch_unwind)]
pub fn fixture_jwe(
    header_json: String,
    payload: String,
    recipient_role: FixtureKey,
) -> napi::Result<String> {
    Ok(test_fixtures::jwe(
        &json("header", &header_json)?,
        payload.as_bytes(),
        recipient_role.jwk(),
    ))
}

#[napi(catch_unwind)]
pub fn fixture_jwks(roles: Vec<FixtureKey>) -> napi::Result<String> {
    let keys: Vec<&JWK> = roles.into_iter().map(FixtureKey::jwk).collect();
    serde_json::to_string(&test_fixtures::jwks(&keys))
        .map_err(|err| napi::Error::from_reason(err.to_string()))
}

/// `issuer_pem` and `issuer_role` go together; omit both for a self-signed certificate.
#[napi(catch_unwind)]
pub fn fixture_x509(
    spec_json: String,
    role: FixtureKey,
    issuer_pem: Option<String>,
    issuer_role: Option<FixtureKey>,
) -> napi::Result<String> {
    let issuer = match (&issuer_pem, issuer_role) {
        (None, None) => None,
        (Some(pem), Some(issuer_role)) => Some((pem.as_str(), issuer_role.jwk())),
        _ => {
            return Err(napi::Error::from_reason(
                "`issuer_pem` and `issuer_role` are given together",
            ));
        }
    };
    Ok(test_fixtures::x509(
        &json("spec", &spec_json)?,
        role.jwk(),
        issuer,
    ))
}
