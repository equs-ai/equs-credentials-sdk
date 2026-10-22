//! Issuer trust from an ETSI trust list: exports a TS 119 602 LoTE from a local server and
//! verifies an mDL against its anchors.

use crate::utils::fixtures::oid4vp::{
    MDL_CLIENT_ID, MDL_NONCE, mdl_chain, mdl_iaca, mdl_vp_token,
    sample_dcql_query_for_mso_mdoc_vp_request,
};
use crate::utils::helpers::create_did_keymetadata_keyhandle;
use crate::utils::http::HttpClientEmulator;
use equs_sdk::inmem::kms::LocalKms;
use equs_sdk::inmem::nonce::LocalNonceHandler;
use equs_sdk::nonce::Nonce;
use equs_sdk::vc::oid4vp::{
    ClientId, CredentialVerificationMetadata, Error, InternalError, PresentationSession,
    ResolvedPresentationQuery, VerifiedPresentationResponse, Verifier, VerifierBuilder,
};
use equs_sdk::vc::trust::issuer::{
    CredentialCategory, CredentialClassification, IssuerTrustMode, IssuerTrustReason,
    IssuerTrustStatus, TrustAnchor,
};
use equs_sdk::vc::trust::list::{
    AnchorRole, ExportOptions, TrustListExport, TrustListKind, export_trust_list_with_client,
};
use oauth2::HttpResponse;
use oauth2::http::HeaderValue;
use oauth2::http::header::CONTENT_TYPE;
use rstest::rstest;
use serde_json::json;
use std::sync::Arc;
use url::Url;

const LOTE_URL: &str = "https://lote.example.com/pid-providers.jwt";

/// Serves a PID providers LoTE listing `iaca` at [LOTE_URL] and exports it pinned to its signer.
async fn export_pid_lote(iaca: &str) -> TrustListExport {
    let signer_key = test_fixtures::JWK::generate_p256();
    let signer = test_fixtures::x509(
        &json!({
            "subject": [["CN", "LoTE Scheme Operator"], ["C", "DE"]],
            "not_before": "2026-01-01", "not_after": "2046-01-01",
            "key_usages": ["digital_signature"]
        }),
        &signer_key,
        None,
    );
    let lote = test_fixtures::lote(
        &json!({
            "lote_type": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
            "entities": [{ "name": "Test PID Provider", "certificates": [iaca] }]
        }),
        &signer,
        &signer_key,
    );

    let mut server = HttpClientEmulator::new();
    server.add_handler(
        Url::parse(LOTE_URL).unwrap(),
        Box::new(move |_| {
            let mut response = HttpResponse::new(lote.clone().into_bytes());
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/jwt"));
            Ok(response)
        }),
    );

    export_trust_list_with_client(
        Arc::new(server),
        LOTE_URL,
        TrustListKind::Lote119602,
        &ExportOptions {
            trust_anchors: vec![signer],
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

/// The LoTE lists PID providers, so the mDL docType is classified as a PID here (by default it is
/// an EAA).
const MDL_AS_PID: bool = true;

async fn verify_mdl_against(
    export: &TrustListExport,
    mode: IssuerTrustMode,
    ds: &str,
    ds_key: &test_fixtures::JWK,
) -> Result<VerifiedPresentationResponse, Error> {
    verify_mdl_classified(export, mode, ds, ds_key, MDL_AS_PID).await
}

async fn verify_mdl_classified(
    export: &TrustListExport,
    mode: IssuerTrustMode,
    ds: &str,
    ds_key: &test_fixtures::JWK,
    mdl_as_pid: bool,
) -> Result<VerifiedPresentationResponse, Error> {
    let kms = LocalKms::new();
    let (did, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;
    let mut builder = VerifierBuilder::new(
        kms,
        LocalNonceHandler::default(),
        key_metadata,
        ClientId::from_did(&did).unwrap(),
    )
    .with_issuer_trust_mode(mode);
    if mdl_as_pid {
        builder = builder.with_credential_classification(CredentialClassification {
            pid: vec!["org.iso.18013.5.1.mDL".to_string()],
            ..Default::default()
        });
    }
    for anchor in export.anchors.iter().map(TrustAnchor::from) {
        builder = builder
            .add_trust_anchor(
                anchor.pem.as_bytes(),
                anchor.source_ref,
                anchor.role,
                anchor.service_type,
            )
            .unwrap();
    }
    let verifier = builder.build().await.unwrap();

    let session = PresentationSession {
        nonce: Nonce::from_secret(MDL_NONCE.to_string()),
        resolved_presentation_query: ResolvedPresentationQuery::DCQL(
            sample_dcql_query_for_mso_mdoc_vp_request(),
        ),
        auth_request_jwt: Default::default(),
    };
    let auth_response =
        serde_json::from_value(json!({ "vp_token": { "mDL": [mdl_vp_token(ds, ds_key)] } }))
            .unwrap();

    verifier
        .verify_and_extract_presentation_with_issuer_trust(
            &auth_response,
            &session,
            &CredentialVerificationMetadata {
                transaction_data: None,
                audience: Some(MDL_CLIENT_ID.to_string()),
            },
        )
        .await
}

#[tokio::test]
async fn lote_export_grants_its_pid_providers_with_role_and_source() {
    let (iaca, _, _) = mdl_chain();

    let export = export_pid_lote(&iaca).await;

    assert!(!export.unpinned);
    assert!(export.skipped_members.is_empty());
    assert_eq!(export.anchors.len(), 1);
    let anchor = &export.anchors[0];
    assert_eq!(anchor.role, Some(AnchorRole::PidProvider));
    assert_eq!(anchor.source_url, LOTE_URL);
    assert_eq!(anchor.entity_name.as_deref(), Some("Test PID Provider"));
}

#[rstest]
#[case::enforce(IssuerTrustMode::Enforce)]
#[case::report(IssuerTrustMode::Report)]
#[tokio::test]
async fn mdl_issued_under_a_listed_iaca_is_trusted(#[case] mode: IssuerTrustMode) {
    let (iaca, ds, ds_key) = mdl_chain();
    let export = export_pid_lote(&iaca).await;

    let verified = verify_mdl_against(&export, mode, &ds, &ds_key)
        .await
        .unwrap();

    let claims = &verified.claims["vp_token"]["mDL"].as_vec().unwrap()[0]["org.iso.18013.5.1"];
    assert_eq!(claims["family_name"].as_str(), Some("Mustermann"));
    let trust = &verified.issuer_trust[0];
    assert_eq!((trust.credential_id.as_str(), trust.index), ("mDL", 0));
    assert_eq!(trust.outcome.status, IssuerTrustStatus::Trusted);
    assert_eq!(trust.outcome.source_ref.as_deref(), Some(LOTE_URL));
    assert_eq!(trust.outcome.role.as_deref(), Some("pid_provider"));
    assert_eq!(trust.outcome.category, Some(CredentialCategory::Pid));
}

#[tokio::test]
async fn an_mdl_is_not_trusted_under_pid_provider_anchors_by_default() {
    let (iaca, ds, ds_key) = mdl_chain();
    let export = export_pid_lote(&iaca).await;

    let verified = verify_mdl_classified(&export, IssuerTrustMode::Report, &ds, &ds_key, false)
        .await
        .unwrap();

    let outcome = &verified.issuer_trust[0].outcome;
    assert_eq!(outcome.status, IssuerTrustStatus::Untrusted);
    assert_eq!(
        outcome.reason,
        Some(IssuerTrustReason::NoAnchorsForCategory)
    );
    assert_eq!(outcome.category, Some(CredentialCategory::Eaa));
}

#[tokio::test]
async fn mdl_issued_under_an_unlisted_iaca_is_rejected_under_enforce() {
    let (_, ds, ds_key) = mdl_chain();
    let export = export_pid_lote(&mdl_iaca(&test_fixtures::JWK::generate_p256())).await;

    let error = verify_mdl_against(&export, IssuerTrustMode::Enforce, &ds, &ds_key)
        .await
        .unwrap_err();

    let Error::Internal {
        source: InternalError::IssuerNotTrusted { issuer_trust },
    } = error
    else {
        panic!("expected issuer_not_trusted, got {error:?}");
    };
    assert_eq!(issuer_trust.len(), 1);
    assert_eq!(issuer_trust[0].outcome.status, IssuerTrustStatus::Untrusted);
    assert_eq!(
        issuer_trust[0].outcome.reason,
        Some(IssuerTrustReason::NoAnchorMatch)
    );
}

#[tokio::test]
async fn mdl_issued_under_an_unlisted_iaca_is_reported_under_report() {
    let (_, ds, ds_key) = mdl_chain();
    let export = export_pid_lote(&mdl_iaca(&test_fixtures::JWK::generate_p256())).await;

    let verified = verify_mdl_against(&export, IssuerTrustMode::Report, &ds, &ds_key)
        .await
        .unwrap();

    let claims = &verified.claims["vp_token"]["mDL"].as_vec().unwrap()[0]["org.iso.18013.5.1"];
    assert_eq!(claims["given_name"].as_str(), Some("Erika"));
    let outcome = &verified.issuer_trust[0].outcome;
    assert_eq!(outcome.status, IssuerTrustStatus::Untrusted);
    assert_eq!(outcome.reason, Some(IssuerTrustReason::NoAnchorMatch));
    assert_eq!(outcome.source_ref, None);
}
