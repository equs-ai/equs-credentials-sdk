use crate::nonce::Nonce;
use crate::vc::core::Result;
use crate::vc::core::{FormatNotSupportedSnafu, VCSnafu, Verifier};
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::formats::{VerifyOptions, API};
use crate::vc::{Claims, Presentation};
use async_trait::async_trait;
use snafu::ResultExt;
use tracing::{instrument, Level};

pub struct VerifierService {
    verifier_id: String,
}

#[async_trait]
impl Verifier for VerifierService {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
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
                JsonLdAPI::verify_vp(vp, nonce, &self.verifier_id, VerifyOptions {})
                    .await
                    .context(VCSnafu)
            }
            _ => FormatNotSupportedSnafu { format: "" }.fail(),
        }?;

        Ok(cred_claims)
    }
}

impl VerifierService {
    #[instrument(
        level = Level::TRACE,
    )]
    pub fn new(verifier_id: &str) -> Self {
        Self {
            verifier_id: verifier_id.to_owned(),
        }
    }
}
