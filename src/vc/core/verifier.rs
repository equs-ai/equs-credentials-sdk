use crate::nonce::Nonce;
use crate::vc::claims::Claims;
use crate::vc::core::api::{ClaimsSnafu, ParseSnafu};
use crate::vc::core::Result;
use crate::vc::core::{FormatNotSupportedSnafu, VCSnafu, Verifier};
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::formats::{VerifyOptions, API};
use crate::vc::Presentation;
use async_trait::async_trait;
use snafu::ResultExt;
use tracing::{instrument, Level};

pub struct VerifierService {
    verifier_id: String,
}

#[async_trait]
impl Verifier for VerifierService {
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn verify_presentation(
        &self,
        nonce: &Nonce, // same as in create_presentation
        presentation: &Presentation,
    ) -> Result<Claims> {
        let cred_claims: Claims = match presentation {
            Presentation::SdJwtVp(vp) => {
                SdJwtAPI::verify_vp(vp, nonce, &self.verifier_id, VerifyOptions {})
                    .await
                    .context(VCSnafu)
            }
            Presentation::LdpVp(vp) => {
                let _ = JsonLdAPI::verify_vp(vp, nonce, &self.verifier_id, VerifyOptions {})
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
}

impl VerifierService {
    #[instrument(level = Level::TRACE)]
    pub fn new(verifier_id: &str) -> Self {
        Self {
            verifier_id: verifier_id.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
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
        VerifierService::new(VERIFIER_ID)
    }
}
