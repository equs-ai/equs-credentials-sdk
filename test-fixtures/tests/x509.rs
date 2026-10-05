//! `X509Chain` checks; built only with the `x509` feature.

use equs_sdk::crypto::Key;
use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::kms::KeyType;
use serde_json::json;

use test_fixtures::keys::FixtureKey;
use test_fixtures::x509::X509Chain;

mod util;
use util::decode_header;

#[tokio::test]
async fn x509_chain_signs_a_credential_carrying_its_own_cert() -> test_fixtures::Result<()> {
    let kms = LocalKms::new();
    let key = FixtureKey::create_default(&kms).await?;
    let chain = X509Chain::self_signed(&key, "verifier.example")?;

    let mut claims = serde_json::Map::new();
    claims.insert("given_name".to_string(), json!("John"));
    let token = chain.sign_sd_jwt_vc(claims).await?;

    let header = decode_header(&token);
    assert_eq!(header["typ"], "dc+sd-jwt");
    assert_eq!(header["x5c"][0], chain.chain_b64[0]);
    Ok(())
}

#[tokio::test]
async fn x509_chain_leaf_names_the_requested_dns_name() -> test_fixtures::Result<()> {
    let kms = LocalKms::new();
    let key = FixtureKey::create_default(&kms).await?;
    let chain = X509Chain::self_signed(&key, "verifier.example")?;

    assert!(chain.leaf_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(!chain.chain_b64.is_empty());
    Ok(())
}

#[tokio::test]
async fn x509_chain_leaf_certifies_the_signing_key() -> test_fixtures::Result<()> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    let kms = LocalKms::new();
    let key = FixtureKey::create_default(&kms).await?;
    let chain = X509Chain::self_signed(&key, "verifier.example")?;

    // Recompute the subject's raw uncompressed EC point independently of the
    // builder, straight from its public JWK, and check that exact byte run
    // shows up inside the issued certificate. A leaf that certified some
    // other key — the CA key, a stray default, anything but `key` — would not
    // contain this point, so this fails loudly on the bug this builder exists
    // to prevent.
    let jwk = key.handle.jwk().expect("P-256 key exposes a JWK");
    let jwk_json = serde_json::to_value(&jwk).unwrap();
    let x = URL_SAFE_NO_PAD
        .decode(jwk_json["x"].as_str().unwrap())
        .unwrap();
    let y = URL_SAFE_NO_PAD
        .decode(jwk_json["y"].as_str().unwrap())
        .unwrap();
    let mut point = vec![0x04];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    let cert_der = STANDARD.decode(&chain.chain_b64[0]).unwrap();
    assert!(
        cert_der
            .windows(point.len())
            .any(|window| window == point.as_slice()),
        "leaf certificate does not embed the signing key's EC point"
    );
    Ok(())
}

#[tokio::test]
async fn x509_chain_rejects_a_non_p256_subject() {
    let kms = LocalKms::new();
    let key = FixtureKey::create(&kms, KeyType::Ed25519).await.unwrap();

    assert!(
        X509Chain::self_signed(&key, "verifier.example").is_err(),
        "an Ed25519 key cannot be certified by this P-256-only builder"
    );
}
