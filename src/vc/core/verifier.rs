use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::nonce::Nonce;
use crate::vc::claims::Claims;
use crate::vc::core::api::ParseSnafu;
use crate::vc::core::Result;
use crate::vc::core::{
    ClaimsSnafu, CredentialStatusNotSupportedSnafu, FormatNotSupportedSnafu, VCSnafu,
    VCStatusSnafu, Verifier,
};
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::formats::{VerifyOptions, API};
use crate::vc::status_formats::status_list_token_jwt::StatusListJwt;
use crate::vc::status_formats::API as VCStatusFormatsAPI;
use crate::vc::VCStatus;
use crate::vc::{HasClaims, Presentation};
use async_trait::async_trait;
use snafu::ResultExt;
use std::convert::TryFrom;
use tracing::{instrument, Level};

pub struct VerifierService {
    verifier_id: String,
    did_resolver: UniversalResolver,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Verifier for VerifierService {
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn verify_presentation(
        &self,
        nonce: &Nonce, // same as in create_presentation
        presentation: &Presentation,
    ) -> Result<Claims> {
        let cred_claims: Claims = match presentation {
            Presentation::SdJwtVp(vp) => SdJwtAPI::verify_vp(
                vp,
                nonce,
                &self.verifier_id,
                VerifyOptions {
                    selective_claims: Default::default(),
                },
                self.did_resolver.clone(),
            )
            .await
            .context(VCSnafu),
            Presentation::LdpVp(vp) => {
                let _ = JsonLdAPI::verify_vp(
                    vp,
                    nonce,
                    &self.verifier_id,
                    VerifyOptions {
                        selective_claims: Default::default(),
                    },
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;

                let claims = Claims::try_from(serde_json::to_value(vp).context(ParseSnafu)?)
                    .context(ClaimsSnafu)?;

                Ok(claims)
            }
            _ => FormatNotSupportedSnafu { format: "" }.fail(),
        }?;

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

        let status = StatusListJwt::get_vc_status(&claims, http_client, self.did_resolver.clone())
            .await
            .context(VCStatusSnafu)?;

        match status {
            Some(vc_status) => Ok(Some(VCStatus::StatusListToken(vc_status))),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::did::universal::UniversalResolver;
    use crate::inmem::kms::LocalKms;
    use crate::vc::core::tests::fixtures::VERIFIER_ID;
    use crate::vc::core::tests::utils::{random_nonce, CredTestCase};
    use crate::vc::core::{Error, Verifier, VerifierService};
    use rstest::rstest;

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[case::ldp_vc(CredTestCase::ldp_vc())]
    #[tokio::test]
    async fn verifier_verifies_credential_correctly(#[case] case: CredTestCase) {
        let kms = LocalKms::new();

        let nonce = random_nonce().await;

        let vc = case.generate_vc(&kms).await;
        let vp = case.generate_vp(&kms, &vc, &nonce).await;

        let verifier = verifier_service();

        let claims = verifier.verify_presentation(&nonce, &vp).await.unwrap();

        case.assert_verified_claims(&claims).await;
    }

    #[rstest]
    #[case::sd_jwt(CredTestCase::sd_jwt())]
    #[tokio::test]
    async fn verifier_verify_fails_on_invalid_nonce(#[case] case: CredTestCase) {
        let kms = LocalKms::new();

        let nonce1 = random_nonce().await;
        let nonce2 = random_nonce().await;

        let vc = case.generate_vc(&kms).await;
        let vp = case.generate_vp(&kms, &vc, &nonce1).await;

        let verifier = verifier_service();

        let res = verifier.verify_presentation(&nonce2, &vp).await;

        assert!(matches!(res.err(), Some(Error::VC { .. })));
    }

    fn verifier_service() -> impl Verifier {
        VerifierService::new(VERIFIER_ID, UniversalResolver::default())
    }
}
