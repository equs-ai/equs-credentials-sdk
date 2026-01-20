use crate::crypto::{JWK, Key, Signer};
use crate::did::universal::UniversalResolver;
use crate::vc::HasClaims;
use crate::vc::claims::{Claim, Claims};
use crate::vc::core::{HolderBinder, PresentationRestrictionValue};
use crate::vc::formats::{API, HasCredential, JsonSnafu, UnimplementedSnafu, VerifyOptions};
use crate::vc::formats::{PresentationSnafu, Result};
use async_trait::async_trait;
use one_core::config::core_config::VerificationProtocolType;
use one_core::model::did::KeyRole;
use one_core::proto::key_verification::KeyVerification;
use one_core::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use one_core::provider::credential_formatter::model::{CredentialClaimValue, DetailCredential};
use one_core::provider::did_method::provider::DidMethodProviderImpl;
use one_core::provider::presentation_formatter::model::{
    ExtractPresentationCtx, ExtractedPresentation,
};
use one_core::provider::presentation_formatter::{
    PresentationFormatter, mso_mdoc::MsoMdocPresentationFormatter,
};
use one_core::service::key::dto::PublicKeyJwkDTO;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use ssi::dids::DIDURL;
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::Level;
use tracing::instrument;

pub(crate) const DOCTYPE_CLAIM: &str = "doctype";

#[derive(Debug)]
pub struct Credential(String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Presentation {
    pub value: String,
    pub enc_pub_key: Option<JWK>,
}

pub struct VCMetadata {}
pub struct VPMetadata {}

#[derive(Debug)]
pub struct MsoMdocAPI;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl API<Claims, Credential, Presentation, VCMetadata, VPMetadata, Claims> for MsoMdocAPI {
    async fn create_vc<S, K>(
        claims: Claims,
        issuer_data: (&DIDURL, S),
        holder_data: (&DIDURL, K),
        metadata: VCMetadata,
        did_resolver: UniversalResolver,
    ) -> Result<Credential>
    where
        S: Signer + Key,
        K: Key,
    {
        UnimplementedSnafu {
            details: "creation of VC is not implemented for mso_mdoc".to_string(),
        }
        .fail()?
    }

    async fn create_vp<S>(
        credential: &Credential,
        holder_signer: S,
        metadata: VPMetadata,
        did_resolver: UniversalResolver,
    ) -> Result<Presentation>
    where
        S: Signer + Key,
    {
        UnimplementedSnafu {
            details: "creation of VP is not implemented for mso_mdoc".to_string(),
        }
        .fail()?
    }

    async fn verify_vc(
        credential: &Credential,
        opts: VerifyOptions,
        did_resolver: UniversalResolver,
    ) -> Result<()> {
        UnimplementedSnafu {
            details: "verification of VC is not implemented for mso_mdoc".to_string(),
        }
        .fail()?
    }

    async fn verify_vp(
        presentation: &Presentation,
        holder_binder: Option<HolderBinder>,
        opts: VerifyOptions,
        did_resolver: UniversalResolver,
    ) -> Result<Claims> {
        let presentation_formatter = MsoMdocPresentationFormatter::default();

        let verifier_key = if let Some(jwk) = presentation.enc_pub_key.as_ref() {
            let key: PublicKeyJwkDTO =
                serde_json::from_value(serde_json::to_value(jwk).context(JsonSnafu)?)
                    .context(JsonSnafu)?;
            Some(key.into())
        } else {
            None
        };
        let ctx = ExtractPresentationCtx {
            verification_protocol_type: VerificationProtocolType::OpenId4VpFinal1_0,
            nonce: holder_binder.clone().map(|b| b.nonce.secret().to_string()),
            client_id: holder_binder.map(|b| b.verifier_id.to_string()),
            trusted_certs_skids: opts.trusted_certs_skids,
            verifier_key,
            format_nonce: None,
            issuance_date: None,
            expiration_date: None,
            mdoc_session_transcript: None,
            response_uri: None,
        };

        let extracted_vps: ExtractedPresentation = presentation_formatter
            .extract_presentation(
                presentation.value.as_str(),
                Box::new(KeyVerification {
                    did_method_provider: Arc::new(DidMethodProviderImpl::default()),
                    key_algorithm_provider: presentation_formatter.key_algorithm_provider.clone(),
                    certificate_validator: presentation_formatter.certificate_validator.clone(),
                    key_role: KeyRole::Authentication,
                }),
                ctx,
            )
            .await
            .map_err(|e| {
                PresentationSnafu {
                    details: format!("Failed to validate mso_mdoc presentation: {}", e),
                }
                .build()
            })?;

        //TODO: Can we assume that there is only one credential in the presentation?
        let credential = extracted_vps.credentials.first().ok_or_else(|| {
            PresentationSnafu {
                details: "Failed to extract credential from verified mso_mdoc presentation"
                    .to_string(),
            }
            .build()
        })?;

        let verified_claims = MdocFormatter::extract_credentials(
            presentation_formatter.certificate_validator.as_ref(),
            credential,
            false,
        )
        .await
        .map_err(|e| {
            PresentationSnafu {
                details: format!("Failed to extract credential claims: {}", e),
            }
            .build()
        })?;

        if Some(OffsetDateTime::now_utc()) < verified_claims.valid_from {
            PresentationSnafu {
                details: "Credential is not yet valid".to_string(),
            }
            .fail()?
        }

        if Some(OffsetDateTime::now_utc()) > verified_claims.valid_until {
            PresentationSnafu {
                details: "Credential has expired".to_string(),
            }
            .fail()?
        }

        verified_claims.try_into()
    }
}

impl HasClaims<Claims> for Credential {
    fn parse_claims(&self) -> Result<Claims> {
        UnimplementedSnafu {
            details: "parsing claims of credential is not implemented for mso_mdoc".to_string(),
        }
        .fail()?
    }

    fn has_type(&self, type_: PresentationRestrictionValue) -> Result<bool> {
        Ok(true)
    }
}

impl HasCredential<Credential> for Presentation {
    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn get_credential(&self) -> Result<Credential> {
        UnimplementedSnafu {
            details: "getting credentials of presentation is not implemented for mso_mdoc"
                .to_string(),
        }
        .fail()?
    }
}

impl TryFrom<DetailCredential> for Claims {
    type Error = crate::vc::formats::Error;

    fn try_from(value: DetailCredential) -> Result<Self> {
        let mut claims = Claims::new();

        for (name, claim_value) in value.claims.claims {
            claims.insert(name, claim_value.value.into())
        }
        Ok(claims)
    }
}

impl From<CredentialClaimValue> for Claim {
    fn from(value: CredentialClaimValue) -> Self {
        match value {
            CredentialClaimValue::Bool(b) => Claim::Bool(b),
            CredentialClaimValue::Number(n) => Claim::from(serde_json::Value::from(n)),
            CredentialClaimValue::String(s) => Claim::String(s),
            CredentialClaimValue::Array(arr) => {
                Claim::Array(arr.into_iter().map(|v| v.value.into()).collect())
            }
            CredentialClaimValue::Object(map) => {
                Claim::Object(map.into_iter().map(|(k, v)| (k, v.value.into())).collect())
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::did::universal::UniversalResolver;
    use crate::nonce::Nonce;
    use crate::vc::claims::Claim;
    use crate::vc::core::HolderBinder;
    use crate::vc::formats::API;
    use crate::vc::formats::VerifyOptions;
    use crate::vc::formats::mso_mdoc::{MsoMdocAPI, Presentation};
    use std::collections::HashSet;

    pub const SAMPLE_MSO_MDOC_VP: &str = "o2d2ZXJzaW9uYzEuMGZzdGF0dXMAaWRvY3VtZW50c4GjZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbGlzc3VlclNpZ25lZKJqaXNzdWVyQXV0aIRDoQEmoRghglkCmjCCApYwggIboAMCAQICDQyTwf3jQRxcD4pD7XYwCgYIKoZIzj0EAwMwTjE_MD0GA1UEAww2T3BlbklENFZDSSBSb290IGF0IGh0dHBzOi8vaXNzdWVyLm11bHRpcGF6Lm9yZy9yZWNvcmRzMQswCQYDVQQGDAJVUzAeFw0yNjAxMDUxNjE5MTBaFw0yNjA3MDcxNjE5MTBaMDsxOTA3BgNVBAMMME9wZW5JRDRWQ0kgYXQgaHR0cHM6Ly9pc3N1ZXIubXVsdGlwYXoub3JnL2lzc3VlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLYqLHSp4L3fSyU7rgIocQNF3sTRo8W6YNxmmHUpe4_TQBDeQI0RQ3gvXI1vKefhAholZVcz4z4KY7L3m1ZTvqKjgfAwge0wHwYDVR0jBBgwFoAUIRQ2u_Kw50lE0GES78kOKtDQ0LswDgYDVR0PAQH_BAQDAgeAMC4GA1UdEgQnMCWGI2h0dHBzOi8vaXNzdWVyLm11bHRpcGF6Lm9yZy9yZWNvcmRzMEsGA1UdHwREMEIwQKA-oDyGOmh0dHBzOi8vaXNzdWVyLm11bHRpcGF6Lm9yZy9yZWNvcmRzL2NybC9jcmVkZW50aWFsX3NpZ25pbmcwHgYDVR0lAQH_BBQwEgYHKIGMXQUBAgYHKIG1NAQBAjAdBgNVHQ4EFgQU7oZBte_2fucVuDed8zbTskelm8AwCgYIKoZIzj0EAwMDaQAwZgIxAIF1nx7Ym5HbYruDH1pW56iDdwG5r7k5DV43aobpKZwuEhYefbwaeoOwCBWIOu79BgIxAPYHrNeEkCWbB_DbOxAV89P6_-S3IlxVOK7GL7Va0eW3V73N7Pzyh8KpNkgvAKOjCVkCwTCCAr0wggJCoAMCAQICEBmnvlxm4a-t0WOyvvKnKBkwCgYIKoZIzj0EAwMwTjE_MD0GA1UEAww2T3BlbklENFZDSSBSb290IGF0IGh0dHBzOi8vaXNzdWVyLm11bHRpcGF6Lm9yZy9yZWNvcmRzMQswCQYDVQQGDAJVUzAeFw0yNjAxMDUxNjE5MTFaFw00MTAxMDExNjE5MTFaME4xPzA9BgNVBAMMNk9wZW5JRDRWQ0kgUm9vdCBhdCBodHRwczovL2lzc3Vlci5tdWx0aXBhei5vcmcvcmVjb3JkczELMAkGA1UEBgwCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASXasBU--V0cJ07YzaywtDca9kooPt3gCXAqoQaX-_vxvCRJh-EJt0ZiQrP8e4Btx0St4uBBer6blHYw_VvK_UqUw3geRxBBcAgVQBo8V6Yx41oLkD89IUjS95MZi1f03qjgeQwgeEwDgYDVR0PAQH_BAQDAgEGMBIGA1UdEwEB_wQIMAYBAf8CAQAwLgYDVR0SBCcwJYYjaHR0cHM6Ly9pc3N1ZXIubXVsdGlwYXoub3JnL3JlY29yZHMwSwYDVR0fBEQwQjBAoD6gPIY6aHR0cHM6Ly9pc3N1ZXIubXVsdGlwYXoub3JnL3JlY29yZHMvY3JsL2NyZWRlbnRpYWxfc2lnbmluZzAdBgNVHQ4EFgQUIRQ2u_Kw50lE0GES78kOKtDQ0LswHwYDVR0jBBgwFoAUIRQ2u_Kw50lE0GES78kOKtDQ0LswCgYIKoZIzj0EAwMDaQAwZgIxAMdMlwHhhBpOnyCzIxoYFrq3DvPkhlzbTfi8YyeOEpr687KNU0bDLjWKxRDOfkyZFAIxAIa_7CG4zlQYn3I2WDMjR4rcIAicmPuNDLLY17v2HA0s-nQTWeZgIpZR_b6Yzj9rmVkDodgYWQOcp2d2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xrwhYILWQUtSjcjYu4be5Ek5Zv0BJu9XrmnTqRDw6BchlkiCdAlggDdIMHO0G0pT5hOxrFmOlqE_Ofb9m3WKqsTDUafgZBpsHWCBV3hxcQNiYpfyxEXpQqK1A56Aq3m1k8VIJHZlxp2psfARYIEV9Wmuz6FS23nwq-In2rms6OdUxtBF-5FhqUHe5LMz7Clgg2Z65tcoFH1Su6G2cXf6S9oEReVWsPljqsrHmEULytJIAWCAujhEGaQLDXyYA_1owVlbd6ADeVLSYtUOri_Gt8nN06gVYIKF41huCdOE3_attkjBx7d0lhrvqPIAz8RY5S-ZBWzNKC1ggWGPz2_TDq-NjoGa6VjY1OV6_XKctfZpgzUs8_oD0opgGWCAA73jUoizyjZH3uR-fQ_vk61P-rLAE2KgAles-hUEBLgFYIN8XKrHjnHVriyDtX5yD-FSWeFjeDHJvcmojShAKWAc6CVggUXSbve4b6vHKs1Xkrk2tG2Xre3mG2pTQNWvKIuz-FyoDWCCDLQYsB2w4hSYFIZ22YGlFpKxU0RIl_0cgR43_V7uEnw1YIE9akmhOmW59azJnXMRoLMGQloNSHTK9EijH01JsGIvKDFggkz-VTPTLKKWuW4OwawyldhsiDxq45t_zKiWJK3sGr7UOWCB_6j7RZ4aFe-pB9Nqfu1s9eucsQwCX9rSPbVhAxu2Fxm1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIAQr5vL3VRvywjMrXXQGhhAu4PEfBfGXwlvj_IPDT7beIlggct3J3ZaHhGORxk-TPhx3GqSBMHOffGZJzcr4VOc0HnxsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjYtMDEtMTlUMDk6NTM6NTdaaXZhbGlkRnJvbcB0MjAyNi0wMS0xOVQwOTo1Mzo1N1pqdmFsaWRVbnRpbMB0MjAyNi0wMi0xOFQwOTo1Mzo1N1pmc3RhdHVzoW9pZGVudGlmaWVyX2xpc3SiYmlkQfljdXJpeDdodHRwczovL2lzc3Vlci5tdWx0aXBhei5vcmcvaXNzdWVyL2lkZW50aWZpZXJfbGlzdC9fZ3lNWEDc563ueC0Bdoa6DRnH54BtlhrXOws_FpeumJ1nfbXC64EhkIl5pVXRbPmOsJyIlv8WCeS2A4Q-7h-8ImgEkoxuam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWFWkaGRpZ2VzdElEC2ZyYW5kb21QBhHSarPzAk7ZXsqbEGF9IHFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1lbGVsZW1lbnRWYWx1ZWdQaGlsZWFz2BhYWaRoZGlnZXN0SUQFZnJhbmRvbVBOXenRS3B9bsm-uAt0KpPScWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWpGb2dnYm90dG9tbGRldmljZVNpZ25lZKJqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhA52GzZrszBFN8ZP-TebSoDYfelPG0jU_atHL0oVdfZVUSyK5OBaX7JdDy3uOKammI1l72YxtxoKUESknwZtSY_GpuYW1lU3BhY2Vz2BhBoA";
    #[tokio::test]
    async fn verify_vp_works_correctly() {
        let verified_claims = MsoMdocAPI::verify_vp(
            &Presentation {
                value: SAMPLE_MSO_MDOC_VP.to_string(),
                enc_pub_key: None,
            },
            Some(HolderBinder {
                nonce: Nonce::from_secret(
                    "BQlBqrJEK9Mv7VuBwB3oax3t1-tA84QMrt9hBF75Hu4".to_string(),
                ),
                verifier_id: "file://".to_string(),
            }),
            VerifyOptions {
                trusted_certs_skids: Some(HashSet::from([
                    "21:14:36:BB:F2:B0:E7:49:44:D0:61:12:EF:C9:0E:2A:D0:D0:D0:BB".to_lowercase(),
                ])),
                selective_claims: None,
            },
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        assert_eq!(
            verified_claims
                .get("org.iso.18013.5.1")
                .unwrap()
                .get("family_name")
                .unwrap(),
            &Claim::String("Foggbottom".to_string())
        );
    }
}
