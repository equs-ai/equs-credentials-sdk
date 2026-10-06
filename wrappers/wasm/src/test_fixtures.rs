//! Test-only bindings over `equs-test-fixtures` for the JS test suites.

use serde_json::Value;
use test_fixtures::JWK;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub enum FixtureKey {
    Authz,
    Issuer,
    Holder,
    Verifier,
    Secret,
}

impl FixtureKey {
    fn jwk(self) -> &'static JWK {
        crate::utils::set_panic_hook();
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

#[wasm_bindgen(js_name = fixturePublicJwk)]
pub fn fixture_public_jwk(role: FixtureKey) -> Result<String, JsError> {
    serde_json::to_string(&role.jwk().to_public()).map_err(JsError::from)
}

#[wasm_bindgen(js_name = fixtureDidKey)]
pub fn fixture_did_key(role: FixtureKey) -> String {
    test_fixtures::did_key(role.jwk())
}

#[wasm_bindgen(js_name = fixtureDidKeyUrl)]
pub fn fixture_did_key_url(role: FixtureKey) -> String {
    test_fixtures::did_key_url(role.jwk())
}

#[wasm_bindgen(js_name = fixtureJws)]
pub fn fixture_jws(
    header_json: String,
    payload_json: String,
    role: FixtureKey,
) -> Result<String, JsError> {
    Ok(test_fixtures::jws(
        &json(&header_json)?,
        &json(&payload_json)?,
        role.jwk(),
    ))
}

/// `disclosures` are JSON array texts, digested as given.
#[wasm_bindgen(js_name = fixtureSdJwt)]
pub fn fixture_sd_jwt(
    header_json: String,
    claims_json: String,
    disclosures: Vec<String>,
    role: FixtureKey,
) -> Result<String, JsError> {
    let disclosures: Vec<&str> = disclosures.iter().map(String::as_str).collect();
    Ok(test_fixtures::sd_jwt(
        &json(&header_json)?,
        &json(&claims_json)?,
        &disclosures,
        role.jwk(),
    ))
}

#[wasm_bindgen(js_name = fixtureSdJwtKb)]
pub fn fixture_sd_jwt_kb(
    sd_jwt: String,
    header_json: String,
    claims_json: String,
    role: FixtureKey,
) -> Result<String, JsError> {
    Ok(test_fixtures::sd_jwt_kb(
        &sd_jwt,
        &json(&header_json)?,
        &json(&claims_json)?,
        role.jwk(),
    ))
}

#[wasm_bindgen(js_name = fixtureJwe)]
pub fn fixture_jwe(
    header_json: String,
    payload: String,
    recipient_role: FixtureKey,
) -> Result<String, JsError> {
    Ok(test_fixtures::jwe(
        &json(&header_json)?,
        payload.as_bytes(),
        recipient_role.jwk(),
    ))
}

#[wasm_bindgen(js_name = fixtureJwks)]
pub fn fixture_jwks(roles: Vec<FixtureKey>) -> String {
    let keys: Vec<&JWK> = roles.into_iter().map(FixtureKey::jwk).collect();
    test_fixtures::jwks(&keys).to_string()
}

fn json(text: &str) -> Result<Value, JsError> {
    serde_json::from_str(text).map_err(JsError::from)
}
