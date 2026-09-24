//! Round-trip suite: every builder's output is fed to the SDK verifier for that
//! kind, plus one failure case that verifier actually rejects.
//!
//! The suite is what makes the crate self-checking — a fixture that stops
//! matching what the SDK accepts fails here rather than surfacing as a
//! confusing failure in a distant test.
//!
//! Three kinds are missing from this file on purpose. The proof-of-possession,
//! `id_token` and request-object verifiers all live in private SDK modules, so
//! their round-trips are unit tests inside the SDK itself — `src/vc/pop/jwt_pop.rs`,
//! `src/vc/oid4vp/verifier.rs` and `src/vc/oid4vp/holder.rs` — reached through
//! the dev-dependency cycle.

use equs_sdk::Duration;
use equs_sdk::crypto::Key;
use equs_sdk::did::universal::UniversalResolver;
use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::jwe::JweDecrypt;
use equs_sdk::kms::{CreateOptions, KeyType, Kms};
use equs_sdk::nonce::Nonce;
use equs_sdk::vc::Presentation;
use equs_sdk::vc::core::{HolderBinder, Verifier, VerifierService};
use equs_sdk::vc::status_formats::API as StatusFormatsAPI;
use equs_sdk::vc::status_formats::status_list_token_jwt::{StatusListJwt, VCStatus};
use equs_sdk::vc::{VCFormatsAPI, VCFormatsSdJwtAPI};
use serde_json::json;

use test_fixtures::http::StaticHttpClient;
use test_fixtures::id_token::{ID_TOKEN_TYP, IdToken};
use test_fixtures::jwe::Jwe;
use test_fixtures::kb_jwt::KbJwt;
use test_fixtures::keys::FixtureKey;
use test_fixtures::pop::{POP_TYP, ProofOfPossession};
use test_fixtures::request_object::{REQUEST_OBJECT_TYP, RequestObject};
use test_fixtures::sd_jwt_vc::SdJwtVc;
use test_fixtures::status_list::{DEFAULT_STATUS_LIST_URL, StatusListToken};
use test_fixtures::vp_token::VpToken;

mod util;
use util::{decode_header, decode_payload};

// --- keys -------------------------------------------------------------------

#[tokio::test]
async fn keys_cover_every_key_type() {
    let kms = LocalKms::new();

    for key_type in [
        KeyType::Ed25519,
        KeyType::P256,
        KeyType::K256,
        KeyType::Bls12381,
    ] {
        let key = FixtureKey::create(&kms, key_type.clone())
            .await
            .unwrap_or_else(|e| panic!("{key_type} key: {e}"));

        assert!(key.did.starts_with("did:key:"), "{key_type}: {}", key.did);
        assert!(
            key.did_url.to_string().starts_with(&key.did),
            "{key_type}: verification method must belong to the DID"
        );
        assert_eq!(key.key_metadata().kid, key.kid);
    }
}

// --- proof of possession ----------------------------------------------------

#[tokio::test]
async fn pop_carries_the_claims_oid4vci_requires() {
    let kms = LocalKms::new();
    let key = FixtureKey::create(&kms, KeyType::Ed25519).await.unwrap();

    let jwt = ProofOfPossession::builder(&key)
        .audience("https://issuer.example")
        .nonce("c-nonce")
        .build()
        .await
        .unwrap();

    let header = decode_header(&jwt);
    assert_eq!(header["typ"], POP_TYP);
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["kid"], key.did_url.to_string());

    let payload = decode_payload(&jwt);
    assert_eq!(payload["aud"], "https://issuer.example");
    assert_eq!(payload["nonce"], "c-nonce");
    assert!(payload["exp"].as_i64().unwrap() > payload["iat"].as_i64().unwrap());
    assert!(payload.get("iss").is_none(), "iss is omitted unless set");
}

#[tokio::test]
async fn pop_lifetime_can_be_put_in_the_past() {
    let kms = LocalKms::new();
    let key = FixtureKey::create_default(&kms).await.unwrap();

    let jwt = ProofOfPossession::builder(&key)
        .lifetime(Duration::minutes(-5))
        .build()
        .await
        .unwrap();

    let payload = decode_payload(&jwt);
    assert!(
        payload["exp"].as_i64().unwrap() < payload["iat"].as_i64().unwrap(),
        "an expired proof must carry exp < iat"
    );
}

// --- SD-JWT VC --------------------------------------------------------------

#[tokio::test]
async fn sd_jwt_vc_verifies_against_the_sdk() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();
    let holder = FixtureKey::create_default(&kms).await.unwrap();

    let vc = SdJwtVc::builder(&issuer, &holder).build().await.unwrap();

    VCFormatsSdJwtAPI::verify_vc(&vc, Default::default(), UniversalResolver::default())
        .await
        .expect("a fixture credential must satisfy the SDK's own verifier");
}

#[tokio::test]
async fn sd_jwt_vc_is_rejected_under_the_wrong_issuer_key() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();
    let holder = FixtureKey::create_default(&kms).await.unwrap();
    let impostor = FixtureKey::create_default(&kms).await.unwrap();

    let vc = SdJwtVc::builder(&issuer, &holder).build().await.unwrap();

    let error = VCFormatsSdJwtAPI::verify_signature(&vc, &impostor.handle.jwk().unwrap())
        .expect_err("a credential must not verify under an unrelated key");
    assert!(!error.to_string().is_empty());
}

// --- KB-JWT -----------------------------------------------------------------

#[tokio::test]
async fn kb_jwt_verifies_against_the_sdk() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();
    let holder = FixtureKey::create_default(&kms).await.unwrap();

    let vc = SdJwtVc::builder(&issuer, &holder).build().await.unwrap();

    let builder = KbJwt::builder(&kms, &holder, vc);
    let binder = builder.holder_binder();
    let vp = builder.build().await.unwrap();

    let claims = VCFormatsSdJwtAPI::verify_vp(
        &vp,
        Some(binder),
        Default::default(),
        UniversalResolver::default(),
    )
    .await
    .expect("a fixture presentation must satisfy the SDK's own verifier");

    assert!(claims.get("name").is_some(), "disclosed claim must survive");
}

#[tokio::test]
async fn kb_jwt_is_rejected_under_a_different_nonce() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();
    let holder = FixtureKey::create_default(&kms).await.unwrap();

    let vc = SdJwtVc::builder(&issuer, &holder).build().await.unwrap();
    let vp = KbJwt::builder(&kms, &holder, vc)
        .nonce("bound-nonce")
        .build()
        .await
        .unwrap();

    VCFormatsSdJwtAPI::verify_vp(
        &vp,
        Some(HolderBinder {
            nonce: Nonce::from_secret("other-nonce".to_string()),
            verifier_id: test_fixtures::claims::DEFAULT_AUDIENCE.to_string(),
            response_uri: None,
        }),
        Default::default(),
        UniversalResolver::default(),
    )
    .await
    .expect_err("a presentation bound to another nonce must be rejected");
}

// --- vp_token ---------------------------------------------------------------

#[tokio::test]
async fn vp_token_verifies_against_the_sdk() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();
    let holder = FixtureKey::create_default(&kms).await.unwrap();

    let vc = SdJwtVc::builder(&issuer, &holder).build().await.unwrap();

    let builder = VpToken::builder(&kms, &holder, vc).bare();
    let binder = builder.holder_binder();
    let vp_token = builder.build().await.unwrap();

    let presentation = vp_token
        .as_str()
        .expect("bare() yields a string")
        .to_string();

    let verifier = VerifierService::new(
        test_fixtures::claims::DEFAULT_AUDIENCE,
        UniversalResolver::default(),
    );
    verifier
        .verify_presentation(
            Some(binder),
            &Presentation::SdJwtVp(presentation),
            &StaticHttpClient::new(),
        )
        .await
        .expect("a fixture vp_token must satisfy the SDK's own verifier");
}

#[tokio::test]
async fn vp_token_keys_presentations_by_dcql_credential_id() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();
    let holder = FixtureKey::create_default(&kms).await.unwrap();

    let vc = SdJwtVc::builder(&issuer, &holder).build().await.unwrap();
    let vp_token = VpToken::builder(&kms, &holder, vc)
        .credential_id("pid")
        .build()
        .await
        .unwrap();

    assert!(
        vp_token["pid"].as_array().is_some_and(|v| v.len() == 1),
        "vp_token must key one presentation under the credential id: {vp_token}"
    );
}

#[tokio::test]
async fn vp_token_is_rejected_under_a_different_nonce() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();
    let holder = FixtureKey::create_default(&kms).await.unwrap();

    let vc = SdJwtVc::builder(&issuer, &holder).build().await.unwrap();
    let vp_token = VpToken::builder(&kms, &holder, vc)
        .nonce("bound-nonce")
        .bare()
        .build()
        .await
        .unwrap();

    let verifier = VerifierService::new(
        test_fixtures::claims::DEFAULT_AUDIENCE,
        UniversalResolver::default(),
    );
    verifier
        .verify_presentation(
            Some(HolderBinder {
                nonce: Nonce::from_secret("other-nonce".to_string()),
                verifier_id: test_fixtures::claims::DEFAULT_AUDIENCE.to_string(),
                response_uri: None,
            }),
            &Presentation::SdJwtVp(vp_token.as_str().unwrap().to_string()),
            &StaticHttpClient::new(),
        )
        .await
        .expect_err("a vp_token bound to another nonce must be rejected");
}

// --- status list token ------------------------------------------------------

#[tokio::test]
async fn status_list_token_verifies_against_the_sdk() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();

    let token = StatusListToken::builder(&issuer)
        .status(1, VCStatus::Invalid)
        .build()
        .await
        .unwrap();

    let http = StaticHttpClient::new().with_response(DEFAULT_STATUS_LIST_URL, token);

    let claims = json!({
        "status": { "status_list": { "idx": 1, "uri": DEFAULT_STATUS_LIST_URL } }
    })
    .try_into()
    .unwrap();

    let status = StatusListJwt::get_vc_status(&claims, &http, UniversalResolver::default(), None)
        .await
        .expect("a fixture status list must satisfy the SDK's own verifier");

    assert_eq!(status, Some(VCStatus::Invalid));
}

#[tokio::test]
async fn status_list_token_is_rejected_for_an_index_outside_the_list() {
    let kms = LocalKms::new();
    let issuer = FixtureKey::create_default(&kms).await.unwrap();

    let token = StatusListToken::builder(&issuer)
        .statuses_nr(32)
        .build()
        .await
        .unwrap();

    let http = StaticHttpClient::new().with_response(DEFAULT_STATUS_LIST_URL, token);

    let claims = json!({
        "status": { "status_list": { "idx": 999, "uri": DEFAULT_STATUS_LIST_URL } }
    })
    .try_into()
    .unwrap();

    StatusListJwt::get_vc_status(&claims, &http, UniversalResolver::default(), None)
        .await
        .expect_err("an index outside the list must be rejected");
}

// --- request object ---------------------------------------------------------

#[tokio::test]
async fn request_object_carries_the_parameters_oid4vp_requires() {
    let kms = LocalKms::new();
    let key = FixtureKey::create_default(&kms).await.unwrap();

    let builder = RequestObject::builder(&key);
    let client_id = builder.resolved_client_id();
    let jwt = builder.build().await.unwrap();

    let header = decode_header(&jwt);
    assert_eq!(header["typ"], REQUEST_OBJECT_TYP);
    assert_eq!(header["kid"], key.did_url.to_string());

    let payload = decode_payload(&jwt);
    assert_eq!(payload["client_id"], client_id);
    assert!(
        client_id.ends_with(&key.did),
        "the kid DID must match client_id: {client_id}"
    );
    for required in [
        "client_id",
        "response_type",
        "response_mode",
        "nonce",
        "aud",
        "dcql_query",
        "client_metadata",
    ] {
        assert!(
            payload.get(required).is_some(),
            "missing required parameter {required}: {payload}"
        );
    }
}

// --- id_token ---------------------------------------------------------------

#[tokio::test]
async fn id_token_carries_the_claims_siop_requires() {
    let kms = LocalKms::new();
    let key = FixtureKey::create_default(&kms).await.unwrap();

    let jwt = IdToken::builder(&key)
        .audience("https://verifier.example")
        .nonce("session-nonce")
        .build()
        .await
        .unwrap();

    let header = decode_header(&jwt);
    assert_eq!(header["typ"], ID_TOKEN_TYP);
    assert_eq!(header["kid"], key.did_url.to_string());

    let payload = decode_payload(&jwt);
    assert_eq!(payload["iss"], key.did);
    assert_eq!(payload["sub"], key.did);
    assert_eq!(payload["aud"], "https://verifier.example");
    assert_eq!(payload["nonce"], "session-nonce");
    assert!(payload["exp"].as_i64().unwrap() > payload["iat"].as_i64().unwrap());
}

// --- JWE --------------------------------------------------------------------

#[tokio::test]
async fn jwe_decrypts_with_the_recipient_key() {
    let kms = LocalKms::new();
    let kid = kms
        .create(KeyType::P256, CreateOptions::default())
        .await
        .unwrap();

    let payload = json!({ "vp_token": "presentation", "state": "abc" });
    let jwe = Jwe::builder(&kms, &kid)
        .payload(payload.clone())
        .build()
        .await
        .unwrap();

    let decrypted = kms
        .decrypt(&jwe, &kid)
        .await
        .expect("a fixture JWE must decrypt with the recipient key");

    assert_eq!(decrypted, payload);
}

#[tokio::test]
async fn jwe_does_not_decrypt_under_a_different_key() {
    let kms = LocalKms::new();
    let recipient = kms
        .create(KeyType::P256, CreateOptions::default())
        .await
        .unwrap();
    let other = kms
        .create(KeyType::P256, CreateOptions::default())
        .await
        .unwrap();

    let jwe = Jwe::builder(&kms, &recipient).build().await.unwrap();

    kms.decrypt(&jwe, &other)
        .await
        .expect_err("a JWE must not decrypt under an unrelated key");
}
