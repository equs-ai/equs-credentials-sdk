//! Round-trip for the delegate SD-JWT builder.
//!
//! Gated on `delegate-sd-jwt`, which forwards to the SDK feature of the same
//! name: without it the SDK has no chain machinery to verify against.

#![cfg(feature = "delegate-sd-jwt")]

use equs_sdk::did::universal::UniversalResolver;
use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::nonce::Nonce;
use equs_sdk::vc::Presentation;
use equs_sdk::vc::claims::{DELEGATIONS_CLAIM, ISSUED_VC_CLAIM};
use equs_sdk::vc::core::{HolderBinder, Verifier, VerifierService};

use test_fixtures::claims::DEFAULT_AUDIENCE;
use test_fixtures::dsd_jwt::DsdJwt;
use test_fixtures::http::StaticHttpClient;
use test_fixtures::keys::FixtureKey;
use test_fixtures::sd_jwt_vc::SdJwtVc;

async fn issued_credential(kms: &LocalKms) -> (FixtureKey, String) {
    let issuer = FixtureKey::create_default(kms).await.unwrap();
    let holder = FixtureKey::create_default(kms).await.unwrap();
    let vc = SdJwtVc::builder(&issuer, &holder).build().await.unwrap();
    (holder, vc)
}

#[tokio::test]
async fn dsd_jwt_verifies_against_the_sdk() {
    let kms = LocalKms::new();
    let (holder, vc) = issued_credential(&kms).await;

    let builder = DsdJwt::builder(&kms, &holder, vc);
    let binder = builder.holder_binder();
    let grant = builder.build().await.unwrap();

    assert!(grant.ends_with('~'), "a dSD-JWT grant must end with '~'");

    let verifier = VerifierService::new(DEFAULT_AUDIENCE, UniversalResolver::default());
    let claims = verifier
        .verify_delegation(
            Some(binder),
            &Presentation::SdJwtVp(grant),
            &StaticHttpClient::new(),
        )
        .await
        .expect("a fixture grant must satisfy the SDK's own delegation verifier");

    assert!(claims.get(ISSUED_VC_CLAIM).is_some());
    assert!(claims.get(DELEGATIONS_CLAIM).is_some());
}

#[tokio::test]
async fn dsd_jwt_is_rejected_under_a_different_nonce() {
    let kms = LocalKms::new();
    let (holder, vc) = issued_credential(&kms).await;

    let grant = DsdJwt::builder(&kms, &holder, vc)
        .nonce("bound-nonce")
        .build()
        .await
        .unwrap();

    let verifier = VerifierService::new(DEFAULT_AUDIENCE, UniversalResolver::default());
    verifier
        .verify_delegation(
            Some(HolderBinder {
                nonce: Nonce::from_secret("other-nonce".to_string()),
                verifier_id: DEFAULT_AUDIENCE.to_string(),
                response_uri: None,
            }),
            &Presentation::SdJwtVp(grant),
            &StaticHttpClient::new(),
        )
        .await
        .expect_err("a grant bound to another nonce must be rejected");
}
