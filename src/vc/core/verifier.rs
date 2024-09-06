use crate::vc::core::Result;
use crate::vc::core::{FormatNotSupportedSnafu, VCSnafu, Verifier};
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::formats::{VerifyOptions, API};
use crate::vc::{Claims, Presentation};
use async_trait::async_trait;
use oid4vci::openidconnect::Nonce;
use snafu::ResultExt;

pub struct VerifierService {
    verifier_id: String,
}

#[async_trait]
impl Verifier for VerifierService {
    async fn verify_presentation(
        &self,
        nonce: &str, // same as in create_presentation
        presentation: &Presentation,
    ) -> Result<Claims> {
        let cred_claims: Claims = match presentation {
            Presentation::SdJwtVp(vp) => SdJwtAPI::verify_vp(
                vp,
                Nonce::new(nonce.into()),
                &self.verifier_id,
                VerifyOptions {},
            )
            .await
            .context(VCSnafu),
            _ => FormatNotSupportedSnafu { format: "" }.fail(),
        }?;

        Ok(cred_claims)
    }
}

impl VerifierService {
    pub fn new(verifier_id: &str) -> Self {
        Self {
            verifier_id: verifier_id.to_owned(),
        }
    }
}
