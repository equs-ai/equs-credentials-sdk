//! `Generator` checks: its fixtures verify against the SDK and against each
//! other.

use equs_sdk::did::universal::UniversalResolver;
use equs_sdk::vc::claims::Claims;
use equs_sdk::vc::status_formats::API as StatusFormatsAPI;
use equs_sdk::vc::status_formats::status_list_token_jwt::{StatusListJwt, VCStatus};

use test_fixtures::generator::Generator;
use test_fixtures::http::StaticHttpClient;

mod util;
use util::decode_payload;

#[tokio::test]
async fn status_pair_resolves_valid_at_the_requested_url() -> test_fixtures::Result<()> {
    let url = "http://localhost:9001/status_list";
    let generator = Generator::new().await?;
    let pair = generator.status_pair(url).await?;

    let claims: Claims = decode_payload(&pair.credential).try_into().unwrap();
    let http = StaticHttpClient::new().with_response(url, pair.status_list_jwt);
    let status = StatusListJwt::get_vc_status(&claims, &http, UniversalResolver::default(), None)
        .await
        .unwrap();

    assert_eq!(status, Some(VCStatus::Valid));
    Ok(())
}

#[tokio::test]
async fn fixtures_share_the_generator_keys() -> test_fixtures::Result<()> {
    let generator = Generator::new().await?;

    let presentation = generator.presentation().await?;
    let access_token = generator.access_token().await?;

    let issuer_jwt = presentation.credential.split('~').next().unwrap();
    assert!(presentation.presentation.starts_with(issuer_jwt));
    assert_eq!(
        decode_payload(&presentation.credential)["iss"],
        generator.issuer_did()
    );
    assert_ne!(access_token, presentation.credential);
    Ok(())
}
