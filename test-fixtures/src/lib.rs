//! Secrets the SDK's tests and demos need at runtime: keys generated once per process, and one
//! generic builder per fixture kind on top of them, so that no token, key or certificate has to
//! be committed to the tree.
//!
//! Call sites keep their own header, claim and parameter values and pass them in; this crate owns
//! only the key material and the cryptography.

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use one_crypto::jwe::{Header as JweHeader, build_jwe};
use one_crypto::signer::ecdsa::ECDSASigner;
use rsa::rand_core::{OsRng, RngCore};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use secrecy::SecretSlice;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ssi::jwk::Params;
use standardized_types::jwk::PublicJwk;
use std::sync::LazyLock;

pub use ssi::JWK;

/// Keys shared by every fixture in the process, each generated on first use.
pub struct Keys {
    /// RSA-2048 key of the authorization server; signs `RS256`, with its JWK thumbprint as `kid`.
    pub authz: LazyLock<JWK>,
    /// P-256 key of the credential issuer.
    pub issuer: LazyLock<JWK>,
    /// P-256 key of the holder.
    pub holder: LazyLock<JWK>,
    /// P-256 key of the verifier.
    pub verifier: LazyLock<JWK>,
    /// 256-bit `HS256` secret.
    pub secret: LazyLock<JWK>,
}

static KEYS: Keys = Keys {
    authz: LazyLock::new(rsa_jwk),
    issuer: LazyLock::new(JWK::generate_p256),
    holder: LazyLock::new(JWK::generate_p256),
    verifier: LazyLock::new(JWK::generate_p256),
    secret: LazyLock::new(secret_jwk),
};

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

/// `did:key` DID of `key` — what a `did:key`-bound token carries as `iss`, `sub` or `aud`.
pub fn did_key(key: &JWK) -> String {
    ssi::dids::DIDKey::generate(key)
        .expect("did:key")
        .to_string()
}

/// base64url(SHA-256(`input`)): the digest of a disclosure, and the `sd_hash` of an SD-JWT.
pub fn digest(input: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

/// Issuer-signed SD-JWT over `header` and `claims`, followed by `disclosures` and a trailing `~`.
/// `_sd` holds the sorted digests of the disclosures plus any digests already in `claims`; a
/// disclosure is the JSON array text `[salt, name, value]` of a top-level claim, digested as given.
pub fn sd_jwt(header: &Value, claims: &Value, disclosures: &[&str], key: &JWK) -> String {
    let mut names = Vec::new();
    for disclosure in disclosures {
        let parts: Vec<Value> = serde_json::from_str(disclosure)
            .unwrap_or_else(|_| panic!("a disclosure is a JSON array, not {disclosure}"));
        let [Value::String(_), Value::String(name), _] = parts.as_slice() else {
            panic!(
                "a disclosure is [salt, name, value] with a string salt and name, not {disclosure}"
            )
        };
        assert!(
            !matches!(name.as_str(), "_sd" | "...") && claims.get(name).is_none(),
            "disclosure name `{name}` is reserved or already a plaintext claim"
        );
        assert!(!names.contains(name), "duplicate disclosure name `{name}`");
        names.push(name.clone());
    }
    let encoded: Vec<String> = disclosures
        .iter()
        .map(|disclosure| BASE64_URL_SAFE_NO_PAD.encode(disclosure))
        .collect();
    let mut claims = claims.clone();
    let mut digests: Vec<String> = optional(&claims["_sd"], "_sd", Value::as_array)
        .into_iter()
        .flatten()
        .map(|digest| {
            optional(digest, "_sd", Value::as_str)
                .expect("`_sd` holds strings")
                .to_string()
        })
        .collect();
    digests.extend(encoded.iter().map(|d| digest(d)));
    digests.sort();
    assert!(
        digests.windows(2).all(|pair| pair[0] != pair[1]),
        "duplicate `_sd` digest"
    );
    if !digests.is_empty() {
        claims["_sd"] = json!(digests);
    }
    let mut token = jws(header, &claims, key);
    for disclosure in &encoded {
        token.push('~');
        token.push_str(disclosure);
    }
    token.push('~');
    token
}

/// `sd_jwt` with key binding: a JWS over `claims` plus the `sd_hash` of `sd_jwt`, signed with
/// the holder `key` under `header` (`typ: kb+jwt`), appended to `sd_jwt`.
pub fn sd_jwt_kb(sd_jwt: &str, header: &Value, claims: &Value, key: &JWK) -> String {
    assert!(sd_jwt.ends_with('~'), "an SD-JWT ends with `~`");
    assert!(
        claims.get("sd_hash").is_none(),
        "`sd_hash` is computed, not given"
    );
    let mut claims = claims.clone();
    claims["sd_hash"] = json!(digest(sd_jwt));
    format!("{sd_jwt}{}", jws(header, &claims, key))
}

/// Compact JWE of `payload` for the P-256 `recipient`: ECDH-ES under a fresh ephemeral key, as the
/// SDK encrypts. `header` gives `kid`, `enc` and the raw `apu` / `apv`; `alg` must be `ECDH-ES`.
pub fn jwe(header: &Value, payload: &[u8], recipient: &JWK) -> String {
    for field in header.as_object().expect("JWE header object").keys() {
        assert!(
            ["alg", "enc", "kid", "apu", "apv"].contains(&field.as_str()),
            "unsupported JWE header field `{field}`"
        );
    }
    assert_eq!(header["alg"], "ECDH-ES", "only ECDH-ES is supported");
    let ephemeral = JWK::generate_p256();
    let shared_secret =
        ECDSASigner::shared_secret_p256(&private_scalar(&ephemeral), &public_jwk(recipient))
            .expect("ECDH");
    let text = |name: &str| optional(&header[name], name, Value::as_str).map(str::to_string);
    build_jwe(
        payload,
        JweHeader {
            key_id: text("kid").expect("`kid`"),
            agreement_partyuinfo: text("apu"),
            agreement_partyvinfo: text("apv"),
        },
        shared_secret,
        public_jwk(&ephemeral),
        serde_json::from_value(header["enc"].clone()).expect("`enc`"),
    )
    .expect("JWE")
}

fn private_scalar(key: &JWK) -> SecretSlice<u8> {
    let Params::EC(ec) = &key.params else {
        panic!("not an EC key")
    };
    SecretSlice::from(ec.ecc_private_key.as_ref().expect("`d`").0.clone())
}

fn public_jwk(key: &JWK) -> PublicJwk {
    serde_json::from_value(serde_json::to_value(key.to_public()).expect("JWK")).expect("public JWK")
}

/// X.509 certificate (PEM) for the P-256 `key`: self-signed, or issued by `issuer`, a CA
/// certificate (PEM) with its key, so the certified key is the one that signs with [`jws`] under an
/// `x5c` header. Every `spec` field is optional: `{"subject": [["CN", "..."], ["C", "US"]],
/// "sans": ["a.example"], "not_before": "2026-09-23", "not_after": "2046-09-18",
/// "ca": true | false | {"path_len": 0}, "key_usages": ["digital_signature", "key_encipherment",
/// "key_cert_sign", "crl_sign"], "extended_key_usages": ["server_auth", "client_auth"],
/// "authority_key_identifier": true}`. The subject keeps the order given, the serial number is
/// random, and a field or value it cannot apply panics.
#[cfg(feature = "x509")]
pub fn x509(spec: &Value, key: &JWK, issuer: Option<(&str, &JWK)>) -> String {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyUsagePurpose, SerialNumber,
    };
    const FIELDS: [&str; 8] = [
        "subject",
        "sans",
        "not_before",
        "not_after",
        "ca",
        "key_usages",
        "extended_key_usages",
        "authority_key_identifier",
    ];
    for field in spec.as_object().expect("certificate spec object").keys() {
        assert!(
            FIELDS.contains(&field.as_str()),
            "unknown certificate spec field `{field}`"
        );
    }
    let list = |name: &str| -> Vec<Value> {
        optional(&spec[name], name, Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let strings = |name: &str| -> Vec<String> {
        list(name)
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .unwrap_or_else(|| panic!("`{name}` holds strings only"))
                    .to_string()
            })
            .collect()
    };
    let date = |name: &str| {
        let text = optional(&spec[name], name, Value::as_str)?;
        let bad = || format!("`{name}` must be a YYYY-MM-DD date, not {text}");
        let [year, month, day] = text.split('-').collect::<Vec<_>>()[..] else {
            panic!("{}", bad())
        };
        Some(rcgen::date_time_ymd(
            year.parse().unwrap_or_else(|_| panic!("{}", bad())),
            month.parse().unwrap_or_else(|_| panic!("{}", bad())),
            day.parse().unwrap_or_else(|_| panic!("{}", bad())),
        ))
    };
    let mut params = CertificateParams::new(strings("sans")).expect("SANs");
    params.distinguished_name = DistinguishedName::new();
    let mut kinds = Vec::new();
    for pair in list("subject") {
        let Some([Value::String(kind), Value::String(value)]) = pair.as_array().map(Vec::as_slice)
        else {
            panic!("`subject` holds [type, value] string pairs, not {pair}")
        };
        assert!(!kinds.contains(kind), "`subject` repeats `{kind}`");
        kinds.push(kind.clone());
        let kind = match kind.as_str() {
            "CN" => DnType::CommonName,
            "C" => DnType::CountryName,
            "O" => DnType::OrganizationName,
            "OU" => DnType::OrganizationalUnitName,
            "L" => DnType::LocalityName,
            "ST" => DnType::StateOrProvinceName,
            other => panic!("unknown DN type `{other}`"),
        };
        params.distinguished_name.push(kind, value.as_str());
    }
    if let Some(not_before) = date("not_before") {
        params.not_before = not_before;
    }
    if let Some(not_after) = date("not_after") {
        params.not_after = not_after;
    }
    params.is_ca = match &spec["ca"] {
        Value::Bool(true) => IsCa::Ca(BasicConstraints::Unconstrained),
        Value::Bool(false) => IsCa::ExplicitNoCa,
        Value::Object(ca) => {
            assert!(
                ca.keys().all(|key| key == "path_len"),
                "`ca` takes only `path_len`"
            );
            let path_len = ca
                .get("path_len")
                .and_then(Value::as_u64)
                .expect("`ca.path_len` must be a non-negative number");
            IsCa::Ca(BasicConstraints::Constrained(
                u8::try_from(path_len).expect("`ca.path_len` must be at most 255"),
            ))
        }
        Value::Null => IsCa::NoCa,
        other => panic!("`ca` must be true, false or {{\"path_len\": n}}, not {other}"),
    };
    params.key_usages = strings("key_usages")
        .iter()
        .map(|usage| match usage.as_str() {
            "digital_signature" => KeyUsagePurpose::DigitalSignature,
            "key_encipherment" => KeyUsagePurpose::KeyEncipherment,
            "key_cert_sign" => KeyUsagePurpose::KeyCertSign,
            "crl_sign" => KeyUsagePurpose::CrlSign,
            other => panic!("unknown key usage `{other}`"),
        })
        .collect();
    params.extended_key_usages = strings("extended_key_usages")
        .iter()
        .map(|usage| match usage.as_str() {
            "server_auth" => ExtendedKeyUsagePurpose::ServerAuth,
            "client_auth" => ExtendedKeyUsagePurpose::ClientAuth,
            other => panic!("unknown extended key usage `{other}`"),
        })
        .collect();
    params.use_authority_key_identifier_extension = optional(
        &spec["authority_key_identifier"],
        "authority_key_identifier",
        Value::as_bool,
    )
    .unwrap_or(false);
    let wants_key_usage = !params.key_usages.is_empty();
    let mut serial = [0u8; 20];
    OsRng.fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    let signing_key = key_pair(key);
    let certificate = match issuer {
        None => params.self_signed(&signing_key),
        Some((ca_pem, ca_key)) => params.signed_by(
            &signing_key,
            &rcgen::Issuer::from_ca_cert_pem(ca_pem, key_pair(ca_key)).expect("CA certificate"),
        ),
    };
    let certificate = certificate.expect("certificate");
    if wants_key_usage {
        let (_, parsed) =
            x509_parser::parse_x509_certificate(certificate.der()).expect("certificate");
        assert!(
            parsed.key_usage().expect("key usage").is_some(),
            "rcgen dropped `key_usages`; add another extension such as `sans` or `ca`"
        );
    }
    certificate.pem()
}

#[cfg(feature = "x509")]
fn key_pair(key: &JWK) -> rcgen::KeyPair {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    let Params::EC(ec) = &key.params else {
        panic!("not an EC key")
    };
    let secret = p256::SecretKey::from_slice(&ec.ecc_private_key.as_ref().expect("`d`").0)
        .expect("P-256 key");
    rcgen::KeyPair::from_pem(
        secret
            .to_pkcs8_pem(LineEnding::LF)
            .expect("PKCS#8")
            .as_str(),
    )
    .expect("key pair")
}

/// `value` through `as_t`, or `None` when it is absent or `null`; any other type panics.
fn optional<'a, T>(
    value: &'a Value,
    name: &str,
    as_t: impl Fn(&'a Value) -> Option<T>,
) -> Option<T> {
    match value {
        Value::Null => None,
        value => {
            Some(as_t(value).unwrap_or_else(|| panic!("`{name}` has the wrong type: {value}")))
        }
    }
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
        "dp": uint(key.dp().expect("dp")), "dq": uint(key.dq().expect("dq")),
        "qi": uint(&key.crt_coefficient().expect("qi")),
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
    fn sd_jwt_reproduces_the_digests_of_an_sdk_issued_credential() {
        let disclosures = [
            r#"["o0TxtL8AhuLRWRgnH984_Q", "given_name", "John"]"#,
            r#"["vIS3esPLyQPtQgBLgOFaag", "family_name", "Doe"]"#,
            r#"["lio5qsUdvI_uwyGbFamNqQ", "dob", "09/09/1989"]"#,
        ];
        let issuer = &keys().issuer;

        let token = sd_jwt(
            &json!({ "typ": "vc+sd-jwt", "alg": "ES256" }),
            &json!({ "vct": "SD_JWT_cred", "_sd_alg": "sha-256" }),
            &disclosures,
            issuer,
        );

        let (issuer_jws, rest) = token.split_once('~').unwrap();
        let encoded: Vec<String> = disclosures
            .iter()
            .map(|d| BASE64_URL_SAFE_NO_PAD.encode(d))
            .collect();
        assert_eq!(rest, format!("{}~", encoded.join("~")));
        let (_, payload) =
            ssi::claims::jws::decode_verify(issuer_jws, &issuer.to_public()).unwrap();
        let claims: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            claims["_sd"],
            json!([
                "CT5o1LfNWDOKOxx42BYG4754lZHy6t0nOPkFEdfoqoM",
                "K7ma0NfqGC_3LPtmvqkrI4yrJlvH4TU69e7Iv-7EIo4",
                "reYaNFBWHzV17cvuq3rFjUI3Gx5Js_DmnUZSERd4hZs"
            ])
        );
        assert_eq!(claims["vct"], "SD_JWT_cred");
    }

    #[test]
    fn sd_jwt_keeps_the_digests_of_undisclosed_claims() {
        let disclosure = r#"["s","a","1"]"#;

        let token = sd_jwt(
            &json!({ "alg": "ES256" }),
            &json!({ "_sd": ["undisclosed-digest"] }),
            &[disclosure],
            &keys().issuer,
        );

        let (issuer_jws, _) = token.split_once('~').unwrap();
        let (_, payload) = ssi::claims::jws::decode_unverified(issuer_jws).unwrap();
        let claims: Value = serde_json::from_slice(&payload).unwrap();
        let sd = claims["_sd"].as_array().unwrap();
        assert_eq!(sd.len(), 2);
        assert!(sd.contains(&json!("undisclosed-digest")));
        assert!(sd.contains(&json!(digest(&BASE64_URL_SAFE_NO_PAD.encode(disclosure)))));
    }

    #[test]
    fn sd_jwt_without_disclosures_has_no_sd_claim() {
        let token = sd_jwt(
            &json!({ "alg": "ES256" }),
            &json!({ "id": "1" }),
            &[],
            &keys().issuer,
        );

        let (issuer_jws, rest) = token.split_once('~').unwrap();

        assert_eq!(rest, "");
        let (_, payload) = ssi::claims::jws::decode_unverified(issuer_jws).unwrap();
        assert_eq!(payload, br#"{"id":"1"}"#);
    }

    #[test]
    fn sd_jwt_kb_binds_the_hash_of_the_presented_sd_jwt() {
        let holder = &keys().holder;
        let sd_jwt = sd_jwt(&json!({ "alg": "ES256" }), &json!({}), &[], &keys().issuer);

        let presentation = sd_jwt_kb(
            &sd_jwt,
            &json!({ "typ": "kb+jwt", "alg": "ES256" }),
            &json!({ "nonce": "n", "aud": "a" }),
            holder,
        );

        let kb_jwt = presentation.strip_prefix(sd_jwt.as_str()).unwrap();
        let (header, payload) =
            ssi::claims::jws::decode_verify(kb_jwt, &holder.to_public()).unwrap();
        let claims: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(header.type_.as_deref(), Some("kb+jwt"));
        assert_eq!(
            claims,
            json!({ "nonce": "n", "aud": "a", "sd_hash": digest(&sd_jwt) })
        );
    }

    #[test]
    fn did_key_is_the_did_of_did_key_url() {
        let url = did_key_url(&keys().verifier);

        assert_eq!(url.split_once('#').unwrap().0, did_key(&keys().verifier));
    }

    #[tokio::test]
    async fn jwe_decrypts_with_the_recipient_key() {
        let verifier = &keys().verifier;
        let header = json!({
            "kid": "ac", "enc": "A128CBC-HS256", "alg": "ECDH-ES", "apu": "some_nonce", "apv": "some_nonce"
        });

        let token = jwe(&header, br#"{"hello":"world"}"#, verifier);

        let protected = BASE64_URL_SAFE_NO_PAD
            .decode(token.split('.').next().unwrap())
            .unwrap();
        let protected: Value = serde_json::from_slice(&protected).unwrap();
        assert_eq!(protected["kid"], "ac");
        assert_eq!(protected["alg"], "ECDH-ES");
        assert_eq!(protected["enc"], "A128CBC-HS256");
        assert_eq!(
            protected["apu"],
            BASE64_URL_SAFE_NO_PAD.encode("some_nonce")
        );
        assert_eq!(protected["epk"]["crv"], "P-256");
        let plaintext =
            one_crypto::jwe::decrypt_jwe_payload(&token, &Recipient(private_scalar(verifier)))
                .await
                .unwrap();
        assert_eq!(plaintext, br#"{"hello":"world"}"#);
    }

    #[test]
    #[should_panic(expected = "only ECDH-ES")]
    fn jwe_rejects_another_alg() {
        jwe(
            &json!({ "kid": "k", "enc": "A128GCM", "alg": "RSA-OAEP" }),
            b"x",
            &keys().verifier,
        );
    }

    #[cfg(feature = "x509")]
    #[test]
    fn x509_issues_a_leaf_for_the_fixture_key_under_a_root() {
        let ca_key = JWK::generate_p256();
        let root = x509(
            &json!({ "subject": [["CN", "Fixture Root CA"]], "ca": true, "key_usages": ["key_cert_sign", "crl_sign"] }),
            &ca_key,
            None,
        );
        let spec = json!({
            "subject": [["C", "US"], ["CN", "Fixture Issuer"]], "sans": ["issuer.example"], "ca": false,
            "not_before": "2026-01-02", "not_after": "2036-01-02",
            "key_usages": ["digital_signature"], "extended_key_usages": ["server_auth"],
            "authority_key_identifier": true
        });

        let cert = x509(&spec, &keys().issuer, Some((&root, &ca_key)));
        let again = x509(&spec, &keys().issuer, Some((&root, &ca_key)));

        let parse = |pem: &str| x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap().1;
        let (root_pem, cert_pem, again_pem) = (parse(&root), parse(&cert), parse(&again));
        let root_x509 = root_pem.parse_x509().unwrap();
        let cert_x509 = cert_pem.parse_x509().unwrap();
        assert_eq!(cert_x509.subject().to_string(), "C=US, CN=Fixture Issuer");
        assert_eq!(
            cert_x509.issuer().to_string(),
            root_x509.subject().to_string()
        );
        assert!(root_x509.is_ca() && !cert_x509.is_ca());
        assert_eq!(cert_x509.validity().not_before.to_datetime().year(), 2026);
        assert!(cert_x509.subject_alternative_name().unwrap().is_some());
        assert!(
            cert_x509
                .extensions()
                .iter()
                .any(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        );
        let Params::EC(ec) = &keys().issuer.params else {
            panic!("not EC")
        };
        let point = [
            &[4u8][..],
            &ec.x_coordinate.as_ref().unwrap().0,
            &ec.y_coordinate.as_ref().unwrap().0,
        ]
        .concat();
        assert_eq!(
            cert_x509.public_key().subject_public_key.data.as_ref(),
            point.as_slice()
        );
        assert_ne!(
            again_pem.parse_x509().unwrap().raw_serial(),
            cert_x509.raw_serial()
        );
    }

    #[cfg(feature = "x509")]
    #[test]
    fn x509_subject_holds_only_the_given_names() {
        let cert = x509(
            &json!({ "subject": [["O", "Acme Co"]] }),
            &keys().issuer,
            None,
        );

        let pem = x509_parser::pem::parse_x509_pem(cert.as_bytes()).unwrap().1;
        assert_eq!(pem.parse_x509().unwrap().subject().to_string(), "O=Acme Co");
    }

    #[cfg(feature = "x509")]
    #[test]
    #[should_panic(expected = "unknown certificate spec field `key_usage`")]
    fn x509_rejects_an_unknown_spec_field() {
        x509(&json!({ "key_usage": [] }), &keys().issuer, None);
    }

    #[cfg(feature = "x509")]
    #[test]
    #[should_panic(expected = "`ca` must be true, false")]
    fn x509_rejects_a_ca_flag_of_the_wrong_type() {
        x509(&json!({ "ca": "true" }), &keys().issuer, None);
    }

    #[test]
    fn authz_key_carries_its_crt_parameters() {
        let jwk = serde_json::to_value(&*keys().authz).unwrap();
        let int = |name: &str| {
            rsa::BigUint::from_bytes_be(
                &BASE64_URL_SAFE_NO_PAD
                    .decode(jwk[name].as_str().unwrap())
                    .unwrap(),
            )
        };
        let one = rsa::BigUint::from(1u8);

        assert_eq!(int("dp"), int("d") % (int("p") - &one));
        assert_eq!(int("dq"), int("d") % (int("q") - &one));
        assert_eq!((int("qi") * int("q")) % int("p"), one);
    }

    #[rstest]
    #[should_panic(expected = "`ca.path_len` must be at most 255")]
    #[case::path_len_out_of_range(json!({ "ca": { "path_len": 256 } }))]
    #[should_panic(expected = "`ca` takes only `path_len`")]
    #[case::unknown_ca_field(json!({ "ca": { "path_length": 0 } }))]
    #[should_panic(expected = "`not_after` must be a YYYY-MM-DD date")]
    #[case::date_without_day(json!({ "not_after": "2046-01" }))]
    #[should_panic(expected = "`subject` holds [type, value] string pairs")]
    #[case::subject_triple(json!({ "subject": [["CN", "x", "y"]] }))]
    #[should_panic(expected = "`subject` repeats `OU`")]
    #[case::repeated_subject_type(json!({ "subject": [["OU", "a"], ["CN", "x"], ["OU", "b"]] }))]
    #[should_panic(expected = "`ca.path_len` must be a non-negative number")]
    #[case::ca_without_path_len(json!({ "ca": {} }))]
    #[should_panic(expected = "rcgen dropped `key_usages`")]
    #[case::key_usages_alone(json!({ "key_usages": ["digital_signature"] }))]
    #[cfg(feature = "x509")]
    fn x509_rejects_a_spec_it_cannot_apply(#[case] spec: Value) {
        x509(&spec, &keys().issuer, None);
    }

    #[rstest]
    #[should_panic(expected = "a disclosure is a JSON array")]
    #[case::not_json(&["salt, name, value"], json!({}))]
    #[should_panic(expected = "a disclosure is [salt, name, value]")]
    #[case::four_parts(&[r#"["salt", "name", "value", "extra"]"#], json!({}))]
    #[should_panic(expected = "a disclosure is [salt, name, value]")]
    #[case::array_element(&[r#"["salt", "value"]"#], json!({}))]
    #[should_panic(expected = "disclosure name `vct` is reserved or already a plaintext claim")]
    #[case::plaintext_clash(&[r#"["salt", "vct", "x"]"#], json!({ "vct": "y" }))]
    #[should_panic(expected = "duplicate disclosure name `name`")]
    #[case::repeated_name(&[r#"["a", "name", "x"]"#, r#"["b", "name", "y"]"#], json!({}))]
    #[should_panic(expected = "duplicate `_sd` digest")]
    #[case::duplicate_digest(&[r#"["salt", "name", "John"]"#], json!({ "_sd": [digest(&BASE64_URL_SAFE_NO_PAD.encode(r#"["salt", "name", "John"]"#))] }))]
    #[should_panic(expected = "`_sd` has the wrong type")]
    #[case::sd_not_an_array(&[], json!({ "_sd": "digest" }))]
    fn sd_jwt_rejects_what_it_cannot_apply(#[case] disclosures: &[&str], #[case] claims: Value) {
        sd_jwt(
            &json!({ "alg": "ES256" }),
            &claims,
            disclosures,
            &keys().issuer,
        );
    }

    #[rstest]
    #[should_panic(expected = "an SD-JWT ends with `~`")]
    #[case::plain_jws(jws(&json!({ "alg": "ES256" }), &json!({}), &keys().issuer), json!({}))]
    #[should_panic(expected = "`sd_hash` is computed, not given")]
    #[case::given_sd_hash("jws~".to_string(), json!({ "sd_hash": "x" }))]
    fn sd_jwt_kb_rejects_what_it_cannot_apply(#[case] sd_jwt: String, #[case] claims: Value) {
        sd_jwt_kb(
            &sd_jwt,
            &json!({ "alg": "ES256", "typ": "kb+jwt" }),
            &claims,
            &keys().holder,
        );
    }

    #[test]
    #[should_panic(expected = "unsupported JWE header field `typ`")]
    fn jwe_rejects_a_header_field_it_would_drop() {
        jwe(
            &json!({ "alg": "ECDH-ES", "enc": "A256GCM", "kid": "k", "typ": "JWT" }),
            b"{}",
            &keys().verifier,
        );
    }

    #[test]
    #[should_panic(expected = "signing")]
    fn jws_rejects_an_alg_the_key_cannot_sign() {
        jws(&json!({ "alg": "ES256" }), &json!({}), &keys().authz);
    }

    struct Recipient(SecretSlice<u8>);

    #[async_trait::async_trait]
    impl one_crypto::jwe::PrivateKeyAgreementHandle for Recipient {
        async fn shared_secret(
            &self,
            remote_jwk: &PublicJwk,
        ) -> Result<SecretSlice<u8>, one_crypto::encryption::EncryptionError> {
            ECDSASigner::shared_secret_p256(&self.0, remote_jwk)
        }
    }
}
