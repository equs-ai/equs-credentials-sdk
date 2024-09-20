use agent_sdk::http::HttpClient;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::vc::oid4vci::{
    CredentialOffer, CredentialOfferParams, Holder, HolderBuilder, Issuer, IssuerBuilder,
    IssuerDiscovery,
};

use crate::utils::http::HttpClientEmulator;
use oauth2::http::StatusCode;
use oauth2::HttpResponse;

use crate::utils::fixtures::{
    sample_authorization_metadata, sample_authz_url, sample_issuer_metadata, sample_issuer_url,
};

use oid4vci::core::metadata::IssuerMetadata;
use url::Url;

use super::create_did_keymetadata_keyhandle;

pub async fn build_holder(
    credential_offer: CredentialOfferParams,
    http_client: impl HttpClient,
) -> impl Holder {
    let kms = LocalKms::new();
    let vault = InMemVault::new();

    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;

    HolderBuilder::new(
        kms,
        vault,
        key_metadata,
        "wallet-dev".to_string(),
        IssuerDiscovery::Offer(CredentialOffer::Value { credential_offer }),
    )
    .with_http_client(http_client)
    .build()
    .await
    .unwrap()
}

pub async fn build_issuer(
    metadata: IssuerMetadata,
    http_client: impl HttpClient,
    introspect_ep: Option<Url>,
) -> impl Issuer {
    let kms = LocalKms::new();
    let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;

    let mut builder = IssuerBuilder::new(kms, metadata, key_metadata).with_http_client(http_client);

    if let Some(ep) = introspect_ep {
        builder = builder.token_validation_introspect(ep, None);
    }

    builder.build().await.unwrap()
}

pub fn setup_http_static_handlers(http_client_emulator: &mut HttpClientEmulator) {
    http_client_emulator.add_handler(
        sample_issuer_url()
            .join("/.well-known/openid-credential-issuer")
            .unwrap(),
        Box::new(|_| {
            let resp = sample_issuer_metadata();

            Ok(HttpResponse {
                status_code: StatusCode::OK,
                headers: Default::default(),
                body: serde_json::to_vec(&resp).unwrap(),
            })
        }),
    );

    http_client_emulator.add_handler(
        sample_authz_url()
            .join("/.well-known/openid-configuration")
            .unwrap(),
        Box::new(|_| {
            let authz_url_str = "https://authz-backend.com";
            let resp = sample_authorization_metadata(authz_url_str);

            Ok(HttpResponse {
                status_code: StatusCode::OK,
                headers: Default::default(),
                body: serde_json::to_vec(&resp).unwrap(),
            })
        }),
    );
}
