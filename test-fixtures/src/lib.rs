//! Secrets the SDK's tests and demos need at runtime — keys generated once per process and a
//! generic compact-JWS signer — so that no signed token or key is committed to the tree.
//!
//! Call sites keep their own header and payload values and pass them to [`jws`]; this crate only
//! owns the key material and the signing.

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::rand_core::{OsRng, RngCore};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_json::{Value, json};
use ssi::jwk::Params;
use std::sync::LazyLock;

pub use ssi::JWK;

/// Keys shared by every fixture in the process, generated on first use.
pub struct Keys {
    /// RSA-2048 key of the authorization server; signs `RS256`, with its JWK thumbprint as `kid`.
    pub authz: JWK,
    /// P-256 key of the credential issuer.
    pub issuer: JWK,
    /// P-256 key of the holder.
    pub holder: JWK,
    /// P-256 key of the verifier.
    pub verifier: JWK,
    /// 256-bit `HS256` secret.
    pub secret: JWK,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| Keys {
    authz: rsa_jwk(),
    issuer: JWK::generate_p256(),
    holder: JWK::generate_p256(),
    verifier: JWK::generate_p256(),
    secret: secret_jwk(),
});

/// The process-wide [`Keys`].
pub fn keys() -> &'static Keys {
    &KEYS
}

/// Compact JWS of `payload` under `header`, signed with `key`; `alg` is read from the header.
pub fn jws(header: &Value, payload: &Value, key: &JWK) -> String {
    let input = format!("{}.{}", b64(header), b64(payload));
    let alg = header["alg"].clone();
    let signature = match &key.params {
        Params::Symmetric(params) => jsonwebtoken::crypto::sign(
            input.as_bytes(),
            &jsonwebtoken::EncodingKey::from_secret(&params.key_value.as_ref().expect("`k`").0),
            serde_json::from_value(alg).expect("`alg`"),
        )
        .expect("signing"),
        _ => ssi::claims::jws::sign_bytes_b64(
            serde_json::from_value(alg).expect("`alg`"),
            input.as_bytes(),
            key,
        )
        .expect("signing"),
    };
    format!("{input}.{signature}")
}

/// Public JWK Set of `keys`, as an authorization server publishes it.
pub fn jwks(keys: &[&JWK]) -> Value {
    json!({ "keys": keys.iter().map(|key| key.to_public()).collect::<Vec<_>>() })
}

/// `did:key` URL of `key`'s verification method — the `kid` the SDK resolves a signature against.
pub fn did_key_url(key: &JWK) -> String {
    ssi::dids::DIDKey::generate_url(key)
        .expect("did:key")
        .to_string()
}

fn b64(value: &Value) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("JSON"))
}

fn rsa_jwk() -> JWK {
    let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key generation");
    let uint = |n: &rsa::BigUint| BASE64_URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let [p, q] = key.primes() else {
        unreachable!("two-prime RSA key")
    };
    let mut jwk = JWK::try_from(json!({
        "kty": "RSA", "alg": "RS256", "use": "sig",
        "n": uint(key.n()), "e": uint(key.e()), "d": uint(key.d()), "p": uint(p), "q": uint(q),
    }))
    .expect("RSA JWK");
    jwk.key_id = Some(jwk.thumbprint().expect("thumbprint"));
    jwk
}

fn secret_jwk() -> JWK {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    JWK::try_from(json!({ "kty": "oct", "k": BASE64_URL_SAFE_NO_PAD.encode(secret) }))
        .expect("oct JWK")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::rs256(&keys().authz, "RS256")]
    #[case::es256(&keys().issuer, "ES256")]
    fn jws_verifies_with_the_public_key(#[case] key: &JWK, #[case] alg: &str) {
        let token = jws(
            &json!({ "alg": alg, "typ": "JWT" }),
            &json!({ "iss": "me" }),
            key,
        );

        let (header, payload) = ssi::claims::jws::decode_verify(&token, &key.to_public()).unwrap();

        assert_eq!(header.algorithm.as_str(), alg);
        assert_eq!(header.type_.as_deref(), Some("JWT"));
        assert_eq!(payload, br#"{"iss":"me"}"#);
    }

    #[test]
    fn hs256_jws_verifies_with_the_secret() {
        let token = jws(
            &json!({ "alg": "HS256" }),
            &json!({ "iss": "me" }),
            &keys().secret,
        );

        let Params::Symmetric(params) = &keys().secret.params else {
            panic!("secret is not symmetric")
        };
        let key = jsonwebtoken::DecodingKey::from_secret(&params.key_value.as_ref().unwrap().0);
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.required_spec_claims.clear();
        let claims = jsonwebtoken::decode::<Value>(&token, &key, &validation)
            .unwrap()
            .claims;

        assert_eq!(claims, json!({ "iss": "me" }));
    }

    #[test]
    fn a_token_under_the_key_id_is_verified_by_the_published_jwks() {
        let authz = &keys().authz;
        let token = jws(
            &json!({ "alg": "RS256", "typ": "JWT", "kid": authz.key_id }),
            &json!({ "scope": "x" }),
            authz,
        );
        let set = jwks(&[authz]);

        let published = JWK::try_from(set["keys"][0].clone()).unwrap();
        let (header, _) = ssi::claims::jws::decode_verify(&token, &published).unwrap();

        assert_eq!(header.key_id, authz.key_id);
        assert_eq!(authz.key_id, Some(authz.thumbprint().unwrap()));
        assert_eq!(header.type_.as_deref(), Some("JWT"));
        assert!(set["keys"][0].get("d").is_none());
    }

    #[test]
    fn did_key_url_names_the_key_as_its_own_fragment() {
        let url = did_key_url(&keys().holder);

        let (did, fragment) = url.split_once('#').unwrap();

        assert_eq!(did.strip_prefix("did:key:").unwrap(), fragment);
    }

    #[test]
    #[should_panic(expected = "signing")]
    fn jws_rejects_an_alg_the_key_cannot_sign() {
        jws(&json!({ "alg": "ES256" }), &json!({}), &keys().authz);
    }
}
