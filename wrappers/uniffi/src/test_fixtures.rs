//! Test-only bindings over `equs-test-fixtures` for the Kotlin and Swift test suites.

use crate::common::{Error, Result};
use ::test_fixtures::JWK;
use serde_json::Value;

#[derive(uniffi::Enum)]
pub enum FixtureKey {
    Authz,
    Issuer,
    Holder,
    Verifier,
    Secret,
}

impl FixtureKey {
    fn jwk(self) -> &'static JWK {
        let keys = ::test_fixtures::keys();
        match self {
            FixtureKey::Authz => &keys.authz,
            FixtureKey::Issuer => &keys.issuer,
            FixtureKey::Holder => &keys.holder,
            FixtureKey::Verifier => &keys.verifier,
            FixtureKey::Secret => &keys.secret,
        }
    }
}

fn json(text: &str) -> Result<Value> {
    serde_json::from_str(text).map_err(|err| Error::Parse(err.to_string()))
}

#[uniffi::export]
pub fn fixture_public_jwk(role: FixtureKey) -> Result<String> {
    serde_json::to_string(&role.jwk().to_public()).map_err(|err| Error::Parse(err.to_string()))
}

#[uniffi::export]
pub fn fixture_did_key(role: FixtureKey) -> String {
    ::test_fixtures::did_key(role.jwk())
}

#[uniffi::export]
pub fn fixture_did_key_url(role: FixtureKey) -> String {
    ::test_fixtures::did_key_url(role.jwk())
}

#[uniffi::export]
pub fn fixture_jws(header_json: String, payload_json: String, role: FixtureKey) -> Result<String> {
    Ok(::test_fixtures::jws(
        &json(&header_json)?,
        &json(&payload_json)?,
        role.jwk(),
    ))
}

/// `disclosures` are JSON array texts, digested as given.
#[uniffi::export]
pub fn fixture_sd_jwt(
    header_json: String,
    claims_json: String,
    disclosures: Vec<String>,
    role: FixtureKey,
) -> Result<String> {
    let disclosures: Vec<&str> = disclosures.iter().map(String::as_str).collect();
    Ok(::test_fixtures::sd_jwt(
        &json(&header_json)?,
        &json(&claims_json)?,
        &disclosures,
        role.jwk(),
    ))
}

#[uniffi::export]
pub fn fixture_sd_jwt_kb(
    sd_jwt: String,
    header_json: String,
    claims_json: String,
    role: FixtureKey,
) -> Result<String> {
    Ok(::test_fixtures::sd_jwt_kb(
        &sd_jwt,
        &json(&header_json)?,
        &json(&claims_json)?,
        role.jwk(),
    ))
}

#[uniffi::export]
pub fn fixture_jwe(
    header_json: String,
    payload: String,
    recipient_role: FixtureKey,
) -> Result<String> {
    Ok(::test_fixtures::jwe(
        &json(&header_json)?,
        payload.as_bytes(),
        recipient_role.jwk(),
    ))
}

#[uniffi::export]
pub fn fixture_jwks(roles: Vec<FixtureKey>) -> String {
    let keys: Vec<&JWK> = roles.into_iter().map(FixtureKey::jwk).collect();
    ::test_fixtures::jwks(&keys).to_string()
}

/// `issuer_pem` and `issuer_role` go together; omit both for a self-signed certificate.
#[uniffi::export]
pub fn fixture_x509(
    spec_json: String,
    role: FixtureKey,
    issuer_pem: Option<String>,
    issuer_role: Option<FixtureKey>,
) -> Result<String> {
    let issuer = match (issuer_pem.as_deref(), issuer_role) {
        (Some(pem), Some(issuer_role)) => Some((pem, issuer_role.jwk())),
        (None, None) => None,
        _ => {
            return Err(Error::Parse(
                "issuer_pem and issuer_role go together".to_string(),
            ));
        }
    };
    Ok(::test_fixtures::x509(
        &json(&spec_json)?,
        role.jwk(),
        issuer,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwk(role: FixtureKey) -> Value {
        serde_json::from_str(&fixture_public_jwk(role).unwrap()).unwrap()
    }

    #[test]
    fn public_jwk_is_public_and_authz_carries_its_kid() {
        let authz = jwk(FixtureKey::Authz);
        assert_eq!(authz["kty"], "RSA");
        assert!(authz["kid"].as_str().is_some_and(|kid| !kid.is_empty()));
        assert!(authz.get("d").is_none());
        let holder = jwk(FixtureKey::Holder);
        assert_eq!(holder["crv"], "P-256");
        assert!(holder.get("d").is_none());
    }

    #[test]
    fn did_key_url_names_the_did_key() {
        let did = fixture_did_key(FixtureKey::Verifier);
        let url = fixture_did_key_url(FixtureKey::Verifier);
        assert!(did.starts_with("did:key:z"));
        assert_eq!(url, format!("{did}#{}", &did["did:key:".len()..]));
    }

    #[test]
    fn jws_is_compact_and_deterministic() {
        let header = r#"{"alg":"ES256","typ":"JWT"}"#.to_string();
        let payload = r#"{"sub":"x"}"#.to_string();
        let token = fixture_jws(header.clone(), payload.clone(), FixtureKey::Issuer).unwrap();
        assert_eq!(token.split('.').filter(|part| !part.is_empty()).count(), 3);
        assert_eq!(
            token,
            fixture_jws(header.clone(), payload.clone(), FixtureKey::Issuer).unwrap()
        );
        assert_ne!(
            token,
            fixture_jws(header, payload, FixtureKey::Holder).unwrap()
        );
    }

    #[test]
    fn sd_jwt_appends_the_disclosures_and_a_key_binding() {
        let sd_jwt = fixture_sd_jwt(
            r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#.to_string(),
            r#"{"vct":"x"}"#.to_string(),
            vec![r#"["salt", "name", "John"]"#.to_string()],
            FixtureKey::Issuer,
        )
        .unwrap();
        assert!(sd_jwt.ends_with('~'));
        assert_eq!(sd_jwt.matches('~').count(), 2);
        let presentation = fixture_sd_jwt_kb(
            sd_jwt.clone(),
            r#"{"alg":"ES256","typ":"kb+jwt"}"#.to_string(),
            r#"{"aud":"v","nonce":"n","iat":1}"#.to_string(),
            FixtureKey::Holder,
        )
        .unwrap();
        assert!(presentation.starts_with(&sd_jwt));
        assert!(!presentation.ends_with('~'));
    }

    #[test]
    fn jwe_is_five_parts_for_a_p256_recipient() {
        let token = fixture_jwe(
            r#"{"kid":"k","enc":"A256GCM","alg":"ECDH-ES"}"#.to_string(),
            "{}".to_string(),
            FixtureKey::Verifier,
        )
        .unwrap();
        assert_eq!(token.split('.').count(), 5);
    }

    #[test]
    fn jwks_publishes_the_roles_public_keys() {
        let jwks: Value = serde_json::from_str(&fixture_jwks(vec![FixtureKey::Authz])).unwrap();
        assert_eq!(jwks["keys"].as_array().map(Vec::len), Some(1));
        assert_eq!(jwks["keys"][0]["kid"], jwk(FixtureKey::Authz)["kid"]);
    }

    #[test]
    fn x509_issues_a_leaf_under_a_root() {
        let root = fixture_x509(
            r#"{"subject":[["CN","Root"]],"ca":true}"#.to_string(),
            FixtureKey::Verifier,
            None,
            None,
        )
        .unwrap();
        let leaf = fixture_x509(
            r#"{"subject":[["CN","Leaf"]],"sans":["issuer.example"],"ca":false}"#.to_string(),
            FixtureKey::Issuer,
            Some(root.clone()),
            Some(FixtureKey::Verifier),
        )
        .unwrap();
        assert!(root.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(leaf.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_ne!(root, leaf);
    }

    #[test]
    fn bad_input_is_a_parse_error() {
        assert!(matches!(
            fixture_jws("{".to_string(), "{}".to_string(), FixtureKey::Issuer),
            Err(Error::Parse(_))
        ));
        assert!(matches!(
            fixture_x509(
                "{}".to_string(),
                FixtureKey::Issuer,
                None,
                Some(FixtureKey::Verifier)
            ),
            Err(Error::Parse(_))
        ));
    }
}
