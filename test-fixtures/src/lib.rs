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
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ssi::claims::cose::ciborium::Value as Cbor;
use ssi::jwk::Params;
use standardized_types::jwa::EncryptionAlgorithm;
use standardized_types::jwk::PublicJwk;
use std::collections::HashSet;
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
    let mut names = HashSet::new();
    for disclosure in disclosures {
        let parts: Vec<Value> = serde_json::from_str(disclosure)
            .unwrap_or_else(|_| panic!("a disclosure is a JSON array, not {disclosure}"));
        let [Value::String(_), Value::String(name), _] = parts.as_slice() else {
            panic!("a disclosure is [salt, name, value], not {disclosure}")
        };
        assert!(
            !matches!(name.as_str(), "_sd" | "...") && claims.get(name).is_none(),
            "disclosure name `{name}` is reserved or already a plaintext claim"
        );
        assert!(
            names.insert(name.clone()),
            "duplicate disclosure name `{name}`"
        );
    }
    let encoded: Vec<String> = disclosures
        .iter()
        .map(|disclosure| BASE64_URL_SAFE_NO_PAD.encode(disclosure))
        .collect();
    let mut claims = claims.clone();
    let mut digests = parse::<Option<Vec<String>>>("`_sd`", &claims["_sd"]).unwrap_or_default();
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
    let header: JweFields = parse("JWE header", header);
    assert_eq!(header.alg, "ECDH-ES", "only ECDH-ES is supported");
    let ephemeral = JWK::generate_p256();
    let shared_secret =
        ECDSASigner::shared_secret_p256(&private_scalar(&ephemeral), &public_jwk(recipient))
            .expect("ECDH");
    build_jwe(
        payload,
        JweHeader {
            key_id: header.kid,
            agreement_partyuinfo: header.apu,
            agreement_partyvinfo: header.apv,
        },
        shared_secret,
        public_jwk(&ephemeral),
        header.enc,
    )
    .expect("JWE")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JweFields {
    alg: String,
    enc: EncryptionAlgorithm,
    kid: String,
    apu: Option<String>,
    apv: Option<String>,
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
    let spec: CertSpec = parse("certificate spec", spec);
    let date = |name: &str, text: &str| {
        let bad = || format!("`{name}` must be a YYYY-MM-DD date, not {text}");
        let [year, month, day] = text.split('-').collect::<Vec<_>>()[..] else {
            panic!("{}", bad())
        };
        rcgen::date_time_ymd(
            year.parse().unwrap_or_else(|_| panic!("{}", bad())),
            month.parse().unwrap_or_else(|_| panic!("{}", bad())),
            day.parse().unwrap_or_else(|_| panic!("{}", bad())),
        )
    };
    let mut params = CertificateParams::new(spec.sans.unwrap_or_default()).expect("SANs");
    params.distinguished_name = DistinguishedName::new();
    for (kind, value) in spec.subject.unwrap_or_default() {
        let ty = match kind {
            DnKind::CN => DnType::CommonName,
            DnKind::C => DnType::CountryName,
            DnKind::O => DnType::OrganizationName,
            DnKind::OU => DnType::OrganizationalUnitName,
            DnKind::L => DnType::LocalityName,
            DnKind::ST => DnType::StateOrProvinceName,
        };
        assert!(
            params.distinguished_name.get(&ty).is_none(),
            "`subject` repeats `{kind:?}`"
        );
        params.distinguished_name.push(ty, value);
    }
    if let Some(text) = &spec.not_before {
        params.not_before = date("not_before", text);
    }
    if let Some(text) = &spec.not_after {
        params.not_after = date("not_after", text);
    }
    params.is_ca = match spec.ca {
        None => IsCa::NoCa,
        Some(Value::Bool(true)) => IsCa::Ca(BasicConstraints::Unconstrained),
        Some(Value::Bool(false)) => IsCa::ExplicitNoCa,
        Some(ca) => IsCa::Ca(BasicConstraints::Constrained(
            u8::try_from(parse::<PathLen>("`ca`", &ca).path_len)
                .expect("`ca.path_len` must be at most 255"),
        )),
    };
    params.key_usages = (spec.key_usages.unwrap_or_default().into_iter())
        .map(|usage| match usage {
            KeyUsage::DigitalSignature => KeyUsagePurpose::DigitalSignature,
            KeyUsage::KeyEncipherment => KeyUsagePurpose::KeyEncipherment,
            KeyUsage::KeyCertSign => KeyUsagePurpose::KeyCertSign,
            KeyUsage::CrlSign => KeyUsagePurpose::CrlSign,
        })
        .collect();
    params.extended_key_usages = (spec.extended_key_usages.unwrap_or_default().into_iter())
        .map(|usage| match usage {
            ExtendedKeyUsage::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsage::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
        })
        .collect();
    params.use_authority_key_identifier_extension = spec.authority_key_identifier.unwrap_or(false);
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
    certificate.expect("certificate").pem()
}

#[cfg(feature = "x509")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertSpec {
    subject: Option<Vec<(DnKind, String)>>,
    sans: Option<Vec<String>>,
    not_before: Option<String>,
    not_after: Option<String>,
    ca: Option<Value>,
    key_usages: Option<Vec<KeyUsage>>,
    extended_key_usages: Option<Vec<ExtendedKeyUsage>>,
    authority_key_identifier: Option<bool>,
}

#[cfg(feature = "x509")]
#[derive(Debug, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
enum DnKind {
    CN,
    C,
    O,
    OU,
    L,
    ST,
}

#[cfg(feature = "x509")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathLen {
    path_len: u64,
}

#[cfg(feature = "x509")]
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum KeyUsage {
    DigitalSignature,
    KeyEncipherment,
    KeyCertSign,
    CrlSign,
}

#[cfg(feature = "x509")]
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
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

/// `value` as `T`: a missing required field, an unknown field or a wrong type panics, naming `what`.
fn parse<'a, T: Deserialize<'a>>(what: &str, value: &'a Value) -> T {
    T::deserialize(value).unwrap_or_else(|err| panic!("{what}: {err}"))
}

/// mso_mdoc DeviceResponse (base64url CBOR) of one document, issuer-signed by `issuer` (DS
/// certificate PEM, optionally followed by its chain, and DS key) and device-signed by `device`
/// under an OpenID4VP 1.0 handover. `spec`: `doc_type`, `name_spaces` (string, integer or boolean
/// values), `valid_from` / `valid_until` (`YYYY-MM-DDThh:mm:ssZ`), `client_id`, `nonce`, optional
/// `response_uri` and `verifier_key`. Other input panics.
pub fn mdoc(spec: &Value, issuer: (&str, &JWK), device: &JWK) -> String {
    let spec: MdocSpec = parse("mdoc spec", spec);
    let doc_type = spec.doc_type.as_str();
    let mut name_spaces = Vec::new();
    let mut value_digests = Vec::new();
    for (name_space, elements) in &spec.name_spaces {
        let elements: serde_json::Map<String, Value> = parse("a name space", elements);
        let mut items = Vec::new();
        let mut digests = Vec::new();
        for (digest_id, (identifier, value)) in elements.iter().enumerate() {
            let mut random = [0u8; 32];
            OsRng.fill_bytes(&mut random);
            let item = embed(&cbor_map([
                ("digestID", Cbor::Integer(digest_id.into())),
                ("random", random.to_vec().into()),
                ("elementIdentifier", identifier.as_str().into()),
                ("elementValue", element_value(value)),
            ]));
            digests.push((
                Cbor::Integer(digest_id.into()),
                Sha256::digest(cbor(&item)).to_vec().into(),
            ));
            items.push(item);
        }
        name_spaces.push((name_space.as_str().into(), Cbor::Array(items)));
        value_digests.push((name_space.as_str().into(), Cbor::Map(digests)));
    }
    let mso = cbor_map([
        ("version", "1.0".into()),
        ("digestAlgorithm", "SHA-256".into()),
        ("valueDigests", Cbor::Map(value_digests)),
        ("deviceKeyInfo", cbor_map([("deviceKey", cose_key(device))])),
        ("docType", doc_type.into()),
        (
            "validityInfo",
            cbor_map([
                ("signed", tdate(&spec.valid_from)),
                ("validFrom", tdate(&spec.valid_from)),
                ("validUntil", tdate(&spec.valid_until)),
            ]),
        ),
    ]);
    let (ds_cert, ds_key) = issuer;
    let issuer_auth = cose_sign1(
        Cbor::Map(vec![(33.into(), x5chain(ds_cert))]),
        cbor(&embed(&mso)),
        true,
        ds_key,
    );
    let device_name_spaces = embed(&Cbor::Map(Vec::new()));
    let device_authentication = Cbor::Array(vec![
        "DeviceAuthentication".into(),
        session_transcript(
            &spec.client_id,
            &spec.nonce,
            spec.response_uri.as_deref(),
            spec.verifier_key.as_ref().map(jwk_thumbprint).as_deref(),
        ),
        doc_type.into(),
        device_name_spaces.clone(),
    ]);
    let device_signature = cose_sign1(
        Cbor::Map(Vec::new()),
        cbor(&embed(&device_authentication)),
        false,
        device,
    );
    let response = cbor_map([
        ("version", "1.0".into()),
        (
            "documents",
            Cbor::Array(vec![cbor_map([
                ("docType", doc_type.into()),
                (
                    "issuerSigned",
                    cbor_map([
                        ("nameSpaces", Cbor::Map(name_spaces)),
                        ("issuerAuth", issuer_auth),
                    ]),
                ),
                (
                    "deviceSigned",
                    cbor_map([
                        ("nameSpaces", device_name_spaces),
                        (
                            "deviceAuth",
                            cbor_map([("deviceSignature", device_signature)]),
                        ),
                    ]),
                ),
            ])]),
        ),
        ("status", 0.into()),
    ]);
    BASE64_URL_SAFE_NO_PAD.encode(cbor(&response))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MdocSpec {
    doc_type: String,
    name_spaces: serde_json::Map<String, Value>,
    valid_from: String,
    valid_until: String,
    client_id: String,
    nonce: String,
    response_uri: Option<String>,
    verifier_key: Option<JWK>,
}

fn b64(value: &Value) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("JSON"))
}

/// OpenID4VP 1.0 SessionTranscript as one-core rebuilds it: `OpenID4VPHandover` with `response_uri`
/// (trailing `/` trimmed), `OpenID4VPDCAPIHandover` without.
fn session_transcript(
    client_id: &str,
    nonce: &str,
    response_uri: Option<&str>,
    thumbprint: Option<&[u8]>,
) -> Cbor {
    let thumbprint = thumbprint.map_or(Cbor::Null, |bytes| bytes.to_vec().into());
    let (handover, info) = match response_uri {
        Some(response_uri) => (
            "OpenID4VPHandover",
            vec![
                client_id.trim_end_matches('/').into(),
                nonce.into(),
                thumbprint,
                response_uri.trim_end_matches('/').into(),
            ],
        ),
        None => (
            "OpenID4VPDCAPIHandover",
            vec![client_id.into(), nonce.into(), thumbprint],
        ),
    };
    Cbor::Array(vec![
        Cbor::Null,
        Cbor::Null,
        Cbor::Array(vec![
            handover.into(),
            Sha256::digest(cbor(&Cbor::Array(info))).to_vec().into(),
        ]),
    ])
}

/// RFC 7638 SHA-256 thumbprint of `key` as raw bytes.
fn jwk_thumbprint(key: &JWK) -> Vec<u8> {
    BASE64_URL_SAFE_NO_PAD
        .decode(key.thumbprint().expect("JWK thumbprint"))
        .expect("base64url thumbprint")
}

/// Untagged ES256 COSE_Sign1 over `payload`, which stays in the structure when `attached` and is
/// detached (`nil`) otherwise.
fn cose_sign1(unprotected: Cbor, payload: Vec<u8>, attached: bool, key: &JWK) -> Cbor {
    let protected = cbor(&Cbor::Map(vec![(1.into(), (-7).into())]));
    let sig_structure = Cbor::Array(vec![
        "Signature1".into(),
        protected.clone().into(),
        Cbor::Bytes(Vec::new()),
        payload.clone().into(),
    ]);
    let signature =
        ssi::claims::jws::sign_bytes(ssi::jwk::Algorithm::ES256, &cbor(&sig_structure), key)
            .expect("signing");
    Cbor::Array(vec![
        protected.into(),
        unprotected,
        if attached { payload.into() } else { Cbor::Null },
        signature.into(),
    ])
}

/// EC2 COSE_Key of a P-256 `key`'s public half.
fn cose_key(key: &JWK) -> Cbor {
    let Params::EC(ec) = &key.params else {
        panic!("not an EC key")
    };
    let coordinate = |c: &Option<ssi::jwk::Base64urlUInt>| -> Cbor {
        c.as_ref().expect("EC coordinate").0.clone().into()
    };
    Cbor::Map(vec![
        (1.into(), 2.into()),
        ((-1).into(), 1.into()),
        ((-2).into(), coordinate(&ec.x_coordinate)),
        ((-3).into(), coordinate(&ec.y_coordinate)),
    ])
}

fn element_value(value: &Value) -> Cbor {
    match value {
        Value::String(text) => text.as_str().into(),
        Value::Bool(flag) => (*flag).into(),
        Value::Number(number) if let Some(integer) = number.as_i64() => integer.into(),
        Value::Number(number) if let Some(integer) = number.as_u64() => integer.into(),
        _ => panic!("element value must be a string, integer or boolean"),
    }
}

/// `#6.24(bstr(value))`, CBOR embedded as a byte string.
fn embed(value: &Cbor) -> Cbor {
    Cbor::Tag(24, Box::new(cbor(value).into()))
}

fn cbor_map<const N: usize>(entries: [(&str, Cbor); N]) -> Cbor {
    Cbor::Map(
        entries
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

fn cbor(value: &Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ssi::claims::cose::ciborium::into_writer(value, &mut bytes).expect("CBOR");
    bytes
}

/// One certificate's DER, or an array for a chain.
fn x5chain(pem: &str) -> Cbor {
    let mut certificates: Vec<Cbor> = pem
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .map(|block| {
            let (body, _) = block
                .split_once("-----END CERTIFICATE-----")
                .expect("unterminated PEM certificate");
            let body: String = body.split_whitespace().collect();
            base64::prelude::BASE64_STANDARD
                .decode(body)
                .expect("PEM certificate base64")
                .into()
        })
        .collect();
    match certificates.len() {
        0 => panic!("no PEM certificate"),
        1 => certificates.remove(0),
        _ => Cbor::Array(certificates),
    }
}

/// `#6.0(text)`, UTC whole seconds only.
fn tdate(text: &str) -> Cbor {
    time::PrimitiveDateTime::parse(
        text,
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z"),
    )
    .unwrap_or_else(|err| panic!("date `{text}` is not YYYY-MM-DDThh:mm:ssZ: {err}"));
    Cbor::Tag(0, Box::new(text.into()))
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
    fn x509_writes_key_usages_without_another_extension() {
        let cert = x509(
            &json!({ "key_usages": ["digital_signature"] }),
            &keys().issuer,
            None,
        );

        let pem = x509_parser::pem::parse_x509_pem(cert.as_bytes()).unwrap().1;
        assert!(pem.parse_x509().unwrap().key_usage().unwrap().is_some());
    }

    #[cfg(feature = "x509")]
    #[test]
    #[should_panic(expected = "certificate spec: unknown field `key_usage`")]
    fn x509_rejects_an_unknown_spec_field() {
        x509(&json!({ "key_usage": [] }), &keys().issuer, None);
    }

    #[cfg(feature = "x509")]
    #[test]
    #[should_panic(expected = "`ca`: invalid type: string \"true\"")]
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
    #[should_panic(expected = "`ca`: unknown field `path_length`")]
    #[case::unknown_ca_field(json!({ "ca": { "path_length": 0 } }))]
    #[should_panic(expected = "`not_after` must be a YYYY-MM-DD date")]
    #[case::date_without_day(json!({ "not_after": "2046-01" }))]
    #[should_panic(expected = "certificate spec: invalid length 3")]
    #[case::subject_triple(json!({ "subject": [["CN", "x", "y"]] }))]
    #[should_panic(expected = "`subject` repeats `OU`")]
    #[case::repeated_subject_type(json!({ "subject": [["OU", "a"], ["CN", "x"], ["OU", "b"]] }))]
    #[should_panic(expected = "`ca`: missing field `path_len`")]
    #[case::ca_without_path_len(json!({ "ca": {} }))]
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
    #[should_panic(expected = "`_sd`: invalid type")]
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
    #[should_panic(expected = "JWE header: unknown field `typ`")]
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

    #[test]
    fn mdoc_issuer_auth_signs_the_digest_of_every_item_under_the_ds_certificate() {
        let ds_key = JWK::generate_p256();
        let document = document(&mdoc(&mdl_spec(), (DS_CERT, &ds_key), &keys().holder));
        let issuer_signed = field(&document, "issuerSigned");
        let issuer_auth = field(issuer_signed, "issuerAuth").as_array().unwrap();

        assert_eq!(
            issuer_auth[1],
            Cbor::Map(vec![(33.into(), b"ds-cert".to_vec().into())])
        );
        let payload = issuer_auth[2].as_bytes().unwrap();
        verify_sign1(field(issuer_signed, "issuerAuth"), payload, &ds_key).unwrap();

        let mso = embedded(&decode(payload));
        assert_eq!(
            field(&mso, "docType").as_text(),
            Some("org.iso.18013.5.1.mDL")
        );
        assert_digests(issuer_signed, &mso, "org.iso.18013.5.1", 4);
        let values: Vec<Cbor> = field(field(issuer_signed, "nameSpaces"), "org.iso.18013.5.1")
            .as_array()
            .unwrap()
            .iter()
            .map(|item| field(&embedded(item), "elementValue").clone())
            .collect();
        assert_eq!(
            values,
            vec!["Mustermann".into(), "Erika".into(), true.into(), 42.into()]
        );
    }

    #[test]
    fn mdoc_digests_each_name_space_under_its_own_name() {
        let ds_key = JWK::generate_p256();
        let mut spec = mdl_spec();
        spec["name_spaces"]["org.iso.18013.5.1.aamva"] = json!({ "DHS_compliance": "F" });
        let document = document(&mdoc(&spec, (DS_CERT, &ds_key), &keys().holder));
        let issuer_signed = field(&document, "issuerSigned");
        let issuer_auth = field(issuer_signed, "issuerAuth").as_array().unwrap();
        let mso = embedded(&decode(issuer_auth[2].as_bytes().unwrap()));

        assert_digests(issuer_signed, &mso, "org.iso.18013.5.1", 4);
        assert_digests(issuer_signed, &mso, "org.iso.18013.5.1.aamva", 1);
    }

    #[test]
    fn mdoc_x5chain_holds_every_certificate_of_the_pem_in_order() {
        let chain = format!("{DS_CERT}{IACA_CERT}");

        assert_eq!(
            x5chain(&chain),
            Cbor::Array(vec![b"ds-cert".to_vec().into(), b"iaca".to_vec().into()])
        );
    }

    #[rstest]
    #[case::empty("")]
    #[case::private_key("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")]
    #[case::unterminated("-----BEGIN CERTIFICATE-----\nZHMtY2VydA==\n")]
    #[case::not_base64("-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n")]
    #[should_panic(expected = "PEM certificate")]
    fn mdoc_rejects_an_issuer_pem_without_a_valid_certificate(#[case] pem: &str) {
        let ds_key = JWK::generate_p256();
        mdoc(&mdl_spec(), (pem, &ds_key), &keys().holder);
    }

    #[test]
    fn mdoc_device_signature_is_bound_to_the_client_id_and_nonce() {
        let ds_key = JWK::generate_p256();
        let document = document(&mdoc(&mdl_spec(), (DS_CERT, &ds_key), &keys().holder));
        let device_signed = field(&document, "deviceSigned");
        let signature = field(field(device_signed, "deviceAuth"), "deviceSignature");
        assert_eq!(signature.as_array().unwrap()[2], Cbor::Null);

        let payload =
            |client_id, nonce| device_payload(device_signed, client_id, nonce, None, None);
        let holder = &keys().holder;
        verify_sign1(signature, &payload(CLIENT_ID, NONCE), holder).unwrap();
        assert!(verify_sign1(signature, &payload("https://other.example", NONCE), holder).is_err());
        assert!(verify_sign1(signature, &payload(CLIENT_ID, "another"), holder).is_err());
    }

    #[test]
    fn mdoc_device_signature_with_a_response_uri_is_bound_to_it() {
        let ds_key = JWK::generate_p256();
        let mut spec = mdl_spec();
        spec["response_uri"] = json!(RESPONSE_URI);
        let document = document(&mdoc(&spec, (DS_CERT, &ds_key), &keys().holder));
        let device_signed = field(&document, "deviceSigned");
        let signature = field(field(device_signed, "deviceAuth"), "deviceSignature");

        let payload =
            |response_uri| device_payload(device_signed, CLIENT_ID, NONCE, response_uri, None);
        let holder = &keys().holder;
        verify_sign1(signature, &payload(Some(RESPONSE_URI)), holder).unwrap();
        assert!(
            verify_sign1(
                signature,
                &payload(Some("https://other.example/response")),
                holder
            )
            .is_err()
        );
        assert!(verify_sign1(signature, &payload(None), holder).is_err());
        let transcript = session_transcript(CLIENT_ID, NONCE, Some(RESPONSE_URI), None);
        let handover = transcript.as_array().unwrap()[2].as_array().unwrap();
        assert_eq!(handover[0].as_text(), Some("OpenID4VPHandover"));
    }

    #[test]
    fn mdoc_device_signature_with_a_verifier_key_is_bound_to_its_thumbprint() {
        let ds_key = JWK::generate_p256();
        let mut spec = mdl_spec();
        spec["response_uri"] = json!(RESPONSE_URI);
        spec["verifier_key"] = json!(keys().verifier.to_public());
        let document = document(&mdoc(&spec, (DS_CERT, &ds_key), &keys().holder));
        let device_signed = field(&document, "deviceSigned");
        let signature = field(field(device_signed, "deviceAuth"), "deviceSignature");

        let payload = |thumbprint| {
            device_payload(
                device_signed,
                CLIENT_ID,
                NONCE,
                Some(RESPONSE_URI),
                thumbprint,
            )
        };
        let holder = &keys().holder;
        let thumbprint = jwk_thumbprint(&keys().verifier);
        verify_sign1(signature, &payload(Some(&thumbprint)), holder).unwrap();
        assert!(verify_sign1(signature, &payload(None), holder).is_err());
        let other = jwk_thumbprint(&keys().issuer);
        assert!(verify_sign1(signature, &payload(Some(&other)), holder).is_err());
    }

    #[test]
    fn session_transcript_matches_the_openid4vp_test_vector() {
        // OpenID4VP 1.0, Appendix B.2.6.1.
        let key: JWK = serde_json::from_value(json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "enc", "kid": "1",
            "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
            "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc"
        }))
        .unwrap();

        let transcript = session_transcript(
            "x509_san_dns:example.com",
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            Some("https://example.com/response"),
            Some(&jwk_thumbprint(&key)),
        );

        assert_eq!(
            cbor(&transcript.as_array().unwrap()[2]),
            hex(
                "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
            )
        );
    }

    #[test]
    fn session_transcript_matches_the_one_core_vector() {
        let transcript = session_transcript(
            "https://verifier.example.com:5173",
            "BQlBqrJEK9Mv7VuBwB3oax3t1-tA84QMrt9hBF75Hu4",
            None,
            None,
        );

        let handover = transcript.as_array().unwrap()[2].as_array().unwrap();
        assert_eq!(handover[0].as_text(), Some("OpenID4VPDCAPIHandover"));
        assert_eq!(
            handover[1].as_bytes().unwrap(),
            &hex("47ba35613a5360b58e307bd52c49634e26832dcaf1d0863c90717ad2d8cdc9d7")
        );
    }

    #[test]
    fn session_transcript_drops_a_trailing_slash_only_in_the_openid4vp_handover() {
        assert_eq!(
            session_transcript(
                "https://verifier.example.com/",
                NONCE,
                Some("https://r/"),
                None
            ),
            session_transcript(CLIENT_ID, NONCE, Some("https://r"), None)
        );
        assert_ne!(
            session_transcript("https://verifier.example.com/", NONCE, None, None),
            session_transcript(CLIENT_ID, NONCE, None, None)
        );
    }

    #[test]
    #[should_panic(expected = "mdoc spec: unknown field `docType`")]
    fn mdoc_rejects_an_unknown_spec_field() {
        let ds_key = JWK::generate_p256();
        mdoc(
            &json!({ "docType": "x" }),
            (DS_CERT, &ds_key),
            &keys().holder,
        );
    }

    #[test]
    fn mdoc_element_values_cover_the_full_integer_range() {
        assert_eq!(element_value(&json!(u64::MAX)), Cbor::from(u64::MAX));
        assert_eq!(element_value(&json!(i64::MIN)), Cbor::from(i64::MIN));
    }

    #[rstest]
    #[case::float(json!(1.5))]
    #[case::array(json!(["a"]))]
    #[case::null(json!(null))]
    #[should_panic(expected = "element value must be a string, integer or boolean")]
    fn mdoc_rejects_a_non_scalar_element_value(#[case] value: Value) {
        let ds_key = JWK::generate_p256();
        let mut spec = mdl_spec();
        spec["name_spaces"]["org.iso.18013.5.1"]["family_name"] = value;
        mdoc(&spec, (DS_CERT, &ds_key), &keys().holder);
    }

    #[rstest]
    #[case::fraction("2046-01-01T00:00:00.5Z")]
    #[case::offset("2046-01-01T00:00:00+01:00")]
    #[case::date_only("2046-01-01")]
    #[case::no_such_day("2046-02-30T00:00:00Z")]
    #[should_panic(expected = "is not YYYY-MM-DDThh:mm:ssZ")]
    fn mdoc_rejects_a_date_that_is_not_a_utc_tdate(#[case] date: &str) {
        let ds_key = JWK::generate_p256();
        let mut spec = mdl_spec();
        spec["valid_until"] = json!(date);
        mdoc(&spec, (DS_CERT, &ds_key), &keys().holder);
    }

    /// Fake PEMs: the builder copies the DER without parsing it.
    const DS_CERT: &str = "-----BEGIN CERTIFICATE-----\nZHMtY2VydA==\n-----END CERTIFICATE-----\n";
    const IACA_CERT: &str = "-----BEGIN CERTIFICATE-----\naWFjYQ==\n-----END CERTIFICATE-----\n";
    const CLIENT_ID: &str = "https://verifier.example.com";
    const NONCE: &str = "n-0S6_WzA2Mj";
    const RESPONSE_URI: &str = "https://verifier.example.com/response";

    fn mdl_spec() -> Value {
        json!({
            "doc_type": "org.iso.18013.5.1.mDL",
            "name_spaces": { "org.iso.18013.5.1": {
                "family_name": "Mustermann", "given_name": "Erika",
                "age_over_18": true, "document_number": 42
            } },
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2046-01-01T00:00:00Z",
            "client_id": CLIENT_ID,
            "nonce": NONCE
        })
    }

    /// `count` items in `name_space`, each under its digest in `mso`.
    fn assert_digests(issuer_signed: &Cbor, mso: &Cbor, name_space: &str, count: usize) {
        let items = field(field(issuer_signed, "nameSpaces"), name_space)
            .as_array()
            .unwrap();
        let digests = field(field(mso, "valueDigests"), name_space)
            .as_map()
            .unwrap();
        assert_eq!(items.len(), count);
        assert_eq!(digests.len(), count);
        for item in items {
            let id = field(&embedded(item), "digestID").clone();
            let (_, digest) = digests.iter().find(|(key, _)| key == &id).unwrap();
            assert_eq!(digest, &Cbor::Bytes(Sha256::digest(cbor(item)).to_vec()));
        }
    }

    /// DeviceAuthentication as a verifier rebuilds it.
    fn device_payload(
        device_signed: &Cbor,
        client_id: &str,
        nonce: &str,
        response_uri: Option<&str>,
        thumbprint: Option<&[u8]>,
    ) -> Vec<u8> {
        let authentication = Cbor::Array(vec![
            "DeviceAuthentication".into(),
            session_transcript(client_id, nonce, response_uri, thumbprint),
            "org.iso.18013.5.1.mDL".into(),
            field(device_signed, "nameSpaces").clone(),
        ]);
        cbor(&embed(&authentication))
    }

    fn decode(bytes: &[u8]) -> Cbor {
        ssi::claims::cose::ciborium::from_reader(bytes).unwrap()
    }

    fn field<'a>(map: &'a Cbor, key: &str) -> &'a Cbor {
        map.as_map()
            .unwrap()
            .iter()
            .find(|(name, _)| name.as_text() == Some(key))
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("no `{key}`"))
    }

    fn embedded(value: &Cbor) -> Cbor {
        let Cbor::Tag(24, inner) = value else {
            panic!("not tag 24")
        };
        decode(inner.as_bytes().unwrap())
    }

    fn document(token: &str) -> Cbor {
        let response = decode(&BASE64_URL_SAFE_NO_PAD.decode(token).unwrap());
        field(&response, "documents").as_array().unwrap()[0].clone()
    }

    fn verify_sign1(
        sign1: &Cbor,
        payload: &[u8],
        key: &JWK,
    ) -> Result<(), ssi::claims::jws::Error> {
        let parts = sign1.as_array().unwrap();
        let sig_structure = Cbor::Array(vec![
            "Signature1".into(),
            parts[0].clone(),
            Cbor::Bytes(Vec::new()),
            payload.into(),
        ]);
        ssi::claims::jws::verify_bytes(
            ssi::jwk::Algorithm::ES256,
            &cbor(&sig_structure),
            &key.to_public(),
            parts[3].as_bytes().unwrap(),
        )
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
}
