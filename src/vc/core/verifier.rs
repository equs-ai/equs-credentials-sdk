use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::vc::claims::Claims;
use crate::vc::core::Result;
use crate::vc::core::api::{
    CredentialExpiredSnafu, ExpirationCheckSnafu, ParseSnafu, VCNotValidSnafu,
};
use crate::vc::core::{
    ClaimsSnafu, CredentialStatusNotSupportedSnafu, FormatNotSupportedSnafu, HolderBinder, VCSnafu,
    VCStatusSnafu, Verifier,
};
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::formats::{API, HasCredential, IsExpired, VerifyOptions};
use crate::vc::status_formats::status_list_token_jwt::StatusListJwt;
use crate::vc::status_formats::{API as VCStatusFormatsAPI, status_list_token_jwt};
use crate::vc::{HasClaims, Presentation};
use crate::vc::{HasVPFormat, VCStatus};
use async_trait::async_trait;
use snafu::ResultExt;
use std::convert::TryFrom;
use tracing::{Level, info, instrument};

#[derive(Clone)]
pub struct VerifierService {
    verifier_id: String,
    did_resolver: UniversalResolver,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Verifier for VerifierService {
    #[instrument(level = Level::TRACE, skip(self, http_client), err(), ret())]
    async fn verify_presentation(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation: &Presentation,
        http_client: &dyn HttpClient,
    ) -> Result<Claims> {
        let cred_claims: Claims = match presentation {
            Presentation::SdJwtVp(vp) => {
                let claims = SdJwtAPI::verify_vp(
                    vp,
                    holder_binder,
                    VerifyOptions {
                        selective_claims: Default::default(),
                    },
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;

                if SdJwtAPI::is_expired(&claims).context(ExpirationCheckSnafu)? {
                    CredentialExpiredSnafu.fail()?
                };

                let vc_status = self
                    .obtain_credential_status(presentation, http_client)
                    .await?;

                match vc_status {
                    None => {
                        info!("Verifiable Credential does not contain the status information");
                    }

                    Some(VCStatus::StatusListToken(status_list_token_jwt::VCStatus::Valid)) => {
                        info!("The status of the verifiable credential is valid.");
                    }

                    Some(VCStatus::StatusListToken(status)) => VCNotValidSnafu {
                        details: format!("The status of the verifiable credential is '{status}'"),
                    }
                    .fail()?,
                }

                claims
            }
            Presentation::LdpVp(vp) => {
                JsonLdAPI::verify_vp(
                    vp,
                    holder_binder,
                    VerifyOptions {
                        selective_claims: Default::default(),
                    },
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;

                let claims = Claims::try_from(serde_json::to_value(vp).context(ParseSnafu)?)
                    .context(ClaimsSnafu)?;

                if JsonLdAPI::is_expired(&vp.get_credential().context(ExpirationCheckSnafu)?)
                    .context(ExpirationCheckSnafu)?
                {
                    CredentialExpiredSnafu.fail()?
                }

                claims
            }
            #[cfg(not(target_arch = "wasm32"))]
            Presentation::MsoMdoc(vp) => {
                use crate::vc::formats::mso_mdoc::MsoMdocAPI;

                MsoMdocAPI::verify_vp(
                    &vp.to_owned().into(),
                    holder_binder,
                    VerifyOptions {
                        selective_claims: Default::default(),
                    },
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?
            }
            _ => FormatNotSupportedSnafu {
                format: presentation.format().to_string(),
            }
            .fail()?,
        };

        Ok(cred_claims)
    }

    #[instrument(level = Level::TRACE, skip(self, http_client), err(), ret())]
    async fn obtain_credential_status(
        &self,
        presentation: &Presentation,
        http_client: &dyn HttpClient,
    ) -> Result<Option<VCStatus>> {
        match presentation {
            Presentation::SdJwtVp(vp) => self.obtain_sd_jwt_vc_status(vp, http_client).await,
            _ => CredentialStatusNotSupportedSnafu.fail(),
        }
    }
}

impl VerifierService {
    #[instrument(level = Level::TRACE, skip(did_resolver))]
    pub fn new(verifier_id: &str, did_resolver: UniversalResolver) -> Self {
        Self {
            verifier_id: verifier_id.to_owned(),
            did_resolver,
        }
    }

    #[instrument(level = Level::TRACE, skip(self, http_client), err(), ret())]
    async fn obtain_sd_jwt_vc_status(
        &self,
        presentation: &crate::vc::formats::sd_jwt_vc::Presentation,
        http_client: &dyn HttpClient,
    ) -> Result<Option<VCStatus>> {
        let claims = presentation.parse_claims().context(VCSnafu)?;

        let status =
            StatusListJwt::get_vc_status(&claims, http_client, self.did_resolver.clone(), None)
                .await
                .map_err(|e| {
                    VCStatusSnafu {
                        details: e.to_string(),
                    }
                    .build()
                })?;

        match status {
            Some(vc_status) => Ok(Some(VCStatus::StatusListToken(vc_status))),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::did::didkey::DIDKey;
    use crate::did::universal::UniversalResolver;
    use crate::did::{DID, DIDBuf, DIDResolver};
    use crate::inmem::kms::{KeyHandle, LocalKms};
    use crate::kms::Kms;
    use crate::reqwest::builder::ReqwestClientBuilder;
    use crate::vc::VCStatusesData;
    use crate::vc::core::status_issuer::StatusIssuerService;
    use crate::vc::core::tests::fixtures::VERIFIER_ID;
    use crate::vc::core::tests::utils::{CredTestCase, random_nonce};
    use crate::vc::core::{
        Error, HolderBinder, KeyMetadata, StatusIssuer, StatusIssuerMetadata, StatusListDefinition,
        Verifier, VerifierService,
    };
    use crate::vc::presentation_exchange::StatusSize;
    use crate::vc::status_formats::StatusListFormat;
    use crate::vc::status_formats::status_list_token_jwt::{VCStatus, VCStatuses};
    use crate::{kms, vc};
    use rstest::rstest;
    use std::str::FromStr;
    use url::Url;

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn verifier_verifies_credential_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();

        let nonce = random_nonce().await;

        let (vc, _) = case.generate_vc(&kms, None).await;
        let vp = case.generate_vp(&kms, &vc, Some(nonce.clone())).await;

        let verifier = verifier_service();

        let claims = verifier
            .verify_presentation(
                Some(HolderBinder {
                    nonce,
                    verifier_id: VERIFIER_ID.to_string(),
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims).await;
    }

    #[tokio::test]
    async fn verifier_verifies_credential_correctly_without_holder_binding_for_sd_jwt() {
        let case = CredTestCase::sd_jwt();
        let kms = LocalKms::new();

        let (vc, _) = case.generate_vc(&kms, None).await;
        let vp = case.generate_vp(&kms, &vc, None).await;

        let verifier = verifier_service();

        let claims = verifier
            .verify_presentation(
                None,
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims).await;
    }

    #[should_panic(expected = "Verification error: invalid input: InvalidToken")]
    #[tokio::test]
    async fn verifier_verifies_credential_and_panics_without_holder_binding_for_sd_jwt() {
        let case = CredTestCase::sd_jwt();
        let kms = LocalKms::new();

        let nonce = random_nonce().await;
        let (vc, _) = case.generate_vc(&kms, None).await;
        let vp = case.generate_vp(&kms, &vc, None).await;

        let verifier = verifier_service();

        let claims = verifier
            .verify_presentation(
                Some(HolderBinder {
                    nonce,
                    verifier_id: VERIFIER_ID.to_string(),
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims).await;
    }

    #[rstest]
    #[case::sd_jwt_non_expired(CredTestCase::sd_jwt(), false)]
    #[case::ldp_vc_non_expired(CredTestCase::ldp_vc(), false)]
    #[should_panic(expected = "Credential is expired")]
    #[case::sd_jwt_expired(CredTestCase::sd_jwt(), true)]
    #[should_panic(expected = "Credential is expired")]
    #[case::ldp_vc_expired(CredTestCase::ldp_vc(), true)]
    #[tokio::test]
    async fn verifier_throws_error_on_expired_creds(
        #[case] case: CredTestCase,
        #[case] expire: bool,
    ) {
        let kms = LocalKms::new();

        let nonce = random_nonce().await;

        let (vc, _) = case
            .generate_vc(&kms, expire.then_some(Default::default()))
            .await;
        let vp = case.generate_vp(&kms, &vc, Some(nonce.to_owned())).await;

        let verifier = verifier_service();

        let claims = verifier
            .verify_presentation(
                Some(HolderBinder {
                    nonce,
                    verifier_id: VERIFIER_ID.to_string(),
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims).await;
    }

    #[rstest]
    #[case::sd_jwt_non_revoked(CredTestCase::sd_jwt(), false)]
    #[case::ldp_vc_non_revoked(CredTestCase::ldp_vc(), false)]
    #[should_panic(expected = "Credential is expired")]
    #[case::sd_jwt_expired(CredTestCase::sd_jwt(), true)]
    #[should_panic(expected = "Format ldp_vc does not support status_list")]
    #[case::ldp_vc_expired(CredTestCase::ldp_vc(), true)] // NOT SUPPORTED YET
    #[tokio::test]
    async fn verifier_throws_error_on_revoked_creds(
        #[case] mut case: CredTestCase,
        #[case] revoke: bool,
    ) {
        let server = httpmock::MockServer::start_async().await;

        let host = server.host();
        let port = server.port();
        let server_list_path = "/status_list";

        let status_list_url =
            Url::parse(&format!("http://{host}:{port}{server_list_path}")).unwrap();

        let staus_issuer = build_status_issuer(status_list_url.clone()).await;

        let status_list = issue_status_list_with_revoked_indexes(&staus_issuer, vec![1]).await;

        server
            .mock_async(|when, then| {
                when.method("GET").path(server_list_path);
                then.status(200)
                    .header("content-type", "application/statuslist+jwt")
                    .body(status_list.clone());
            })
            .await;

        if revoke {
            case = case.add_revoked_status(status_list_url);
        }

        let kms = LocalKms::new();
        let nonce = random_nonce().await;

        let (vc, _) = case
            .generate_vc(&kms, revoke.then_some(Default::default()))
            .await;
        let vp = case.generate_vp(&kms, &vc, Some(nonce.to_owned())).await;

        let verifier = verifier_service();

        let claims = verifier
            .verify_presentation(
                Some(HolderBinder {
                    nonce,
                    verifier_id: VERIFIER_ID.to_string(),
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims).await;
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[tokio::test]
    async fn verifier_verify_fails_on_invalid_nonce(#[case] case: CredTestCase) {
        let kms = LocalKms::new();

        let nonce1 = random_nonce().await;
        let nonce2 = random_nonce().await;

        let (vc, _) = case.generate_vc(&kms, None).await;
        let vp = case.generate_vp(&kms, &vc, Some(nonce1)).await;

        let verifier = verifier_service();

        let res = verifier
            .verify_presentation(
                Some(HolderBinder {
                    nonce: nonce2,
                    verifier_id: VERIFIER_ID.to_string(),
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await;

        assert!(matches!(res.err(), Some(Error::VC { .. })));
    }

    fn verifier_service() -> impl Verifier {
        VerifierService::new(VERIFIER_ID, UniversalResolver::default())
    }

    async fn build_status_issuer(status_list_url: Url) -> impl StatusIssuer {
        // Initialization
        println!("Status issuer creating...");

        let kms = LocalKms::new();
        let (_, key_metadata, _) = create_did_keymetadata_keyhandle(&kms).await;

        let metadata = StatusIssuerMetadata {
            issuer_id: "123456".to_string(),
            supported_status_lists: vec![StatusListDefinition {
                id: "test".to_string(),
                format: StatusListFormat::StatusListTokenJwt(
                    vc::status_formats::status_list_token_jwt::SLMetadata {
                        statuses_nr: 32,
                        status_list_url,
                        status_size: StatusSize::try_from(1u8).unwrap(),
                    },
                ),
                key_metadata,
            }],
        };

        StatusIssuerService::new(kms, metadata)
    }

    async fn create_did_keymetadata_keyhandle(kms: &LocalKms) -> (DID, KeyMetadata, KeyHandle) {
        let (kid, kh) = kms
            .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
            .await
            .unwrap();

        let did = DIDKey::generate(kh.clone()).unwrap();

        let vm = UniversalResolver::default()
            .resolve_into_any_verification_method(DIDBuf::from_str(&did).unwrap().as_did())
            .await
            .unwrap()
            .unwrap()
            .id;

        (
            did,
            KeyMetadata {
                kid,
                did_url: vm.to_string(),
            },
            kh,
        )
    }

    async fn issue_status_list_with_revoked_indexes(
        status_issuer: &impl StatusIssuer,
        revoked: Vec<usize>,
    ) -> String {
        let mut statuses = VCStatuses::new();

        for idx in revoked {
            statuses.set(idx, VCStatus::Invalid);
        }

        let status_list = status_issuer
            .issue_status_list("test", VCStatusesData::StatusListToken(statuses))
            .await
            .unwrap();

        let crate::vc::StatusList::StatusListTokenJwt(status_list) = status_list;

        status_list
    }
}
