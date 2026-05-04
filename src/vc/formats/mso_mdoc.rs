use crate::crypto::{JWK, Key, Signer};
use crate::did::universal::UniversalResolver;
use crate::vc::HasClaims;
use crate::vc::claims::{Claim, Claims};
use crate::vc::core::{HolderBinder, PresentationRestrictionValue};
use crate::vc::formats::{API, HasCredential, JsonSnafu, UnimplementedSnafu, VerifyOptions};
use crate::vc::formats::{PresentationSnafu, Result};
use async_trait::async_trait;
use one_core::config::core_config::{KeyAlgorithmType, VerificationProtocolType};
use one_core::model::did::KeyRole;
use one_core::proto::certificate_validator::{CertificateValidator, CertificateValidatorImpl};
use one_core::proto::key_verification::KeyVerification;
use one_core::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use one_core::provider::credential_formatter::model::{CredentialClaimValue, DetailCredential};
use one_core::provider::did_method::provider::DidMethodProviderImpl;
use one_core::provider::key_algorithm::{
    KeyAlgorithm, ecdsa::Ecdsa, eddsa::Eddsa, provider::KeyAlgorithmProviderImpl,
};
use one_core::provider::presentation_formatter::model::{
    ExtractPresentationCtx, ExtractedPresentation,
};
use one_core::provider::presentation_formatter::{
    PresentationFormatter, mso_mdoc::MsoMdocPresentationFormatter,
};
use one_core_asdk::standardized_types::jwk::PublicJwk;
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
        let certificate_validator: Arc<dyn CertificateValidator> =
            Arc::new(CertificateValidatorImpl::default());

        let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(
            std::collections::HashMap::from_iter([
                (
                    KeyAlgorithmType::Eddsa,
                    Arc::new(Eddsa) as Arc<dyn KeyAlgorithm>,
                ),
                (
                    KeyAlgorithmType::Ecdsa,
                    Arc::new(Ecdsa) as Arc<dyn KeyAlgorithm>,
                ),
            ]),
            Default::default(),
        ));

        let presentation_formatter =
            MsoMdocPresentationFormatter::new(certificate_validator.clone(), None);

        let verifier_key = if let Some(jwk) = presentation.enc_pub_key.as_ref() {
            let key: PublicJwk =
                serde_json::from_value(serde_json::to_value(jwk).context(JsonSnafu)?)
                    .context(JsonSnafu)?;
            Some(key)
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
                    key_algorithm_provider: key_algorithm_provider.clone(),
                    certificate_validator: certificate_validator.clone(),
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

        let verified_claims =
            MdocFormatter::extract_credentials(certificate_validator.as_ref(), credential, false)
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
    use crate::vc::VCFormatsAPI;
    use crate::vc::claims::Claim;
    use crate::vc::core::HolderBinder;
    use crate::vc::formats::VerifyOptions;
    use crate::vc::formats::mso_mdoc::{MsoMdocAPI, Presentation};
    use std::collections::HashSet;

    // Generated by one-core/src/provider/credential_formatter/mdoc_formatter/test.rs::generate_asdk_sample_mso_mdoc_vp
    // Certificates have no CRL distribution points and are valid for 10 years.
    // To regenerate: run `cargo test -p one-core --features mock generate_asdk_sample_mso_mdoc_vp -- --ignored --nocapture` in one-core-new
    pub const SAMPLE_MSO_MDOC_VP: &str = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWGqkaGRpZ2VzdElEAGZyYW5kb21YIBfOJf-OpYyXbNcjdEF89NwOUunqJtRcUvly7KAcO222cWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWpNdXN0ZXJtYW5u2BhYZKRoZGlnZXN0SUQBZnJhbmRvbVggdOQTLNgV0Fh1YTqN_0J6MQR1YkX8dKaVxoyALkm396FxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVlRXJpa2FqaXNzdWVyQXV0aIRDoQEmoRghWQF5MIIBdTCCARugAwIBAgIUN1PepVczuWv7XDOcU4b_rxcf4GQwCgYIKoZIzj0EAwIwITESMBAGA1UEAwwJVGVzdCBJQUNBMQswCQYDVQQGDAJVUzAeFw0yNjA0MjMxMDMyNTNaFw0zNjA0MjExMDMyNTNaMB8xEDAOBgNVBAMMB1Rlc3QgRFMxCzAJBgNVBAYMAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGKfQaBLofzWxQTeV3CrA1_x6NyxFTJriIO_WdQREf2-iXCdFth_MXNq-7v241ZoCgxT2QOkGbw2vVybjAU5c-KMzMDEwHwYDVR0jBBgwFoAUXiFrVYFqnFwKeOdU4cqUC3I-oZQwDgYDVR0PAQH_BAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIQCBEQMeGpYogwy4Ek_9RtTpjCeTn_eKGXuvpZPKf8HnpgIgINGEFcgvSef7RixzMN5FENTaD2XUjPeSSjtzGugLZDZZAaTYGFkBn6ZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMaIAWCA19M1pyGzyjkPgmOfeEgSid-gJz_jPCXWgsYgmUFIt8wFYIH6BF4UjAllSbioUOlKuduzEFKl2qVsP8zGL_-W1N0grbWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggxfFsXOz18R9L6UC3WfL-fJDAGjMeeJQVjq2VfHQpCbMiWCDmxXqovtWffMxD7vCUIso6nnSmnCHhwI5pLTZjq_jpe2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWxpZGl0eUluZm-kZnNpZ25lZMB0MjAyNi0wNC0yNFQxMDozMjo1M1ppdmFsaWRGcm9twHQyMDI2LTA0LTI0VDEwOjMyOjUzWmp2YWxpZFVudGlswHQyMDM2LTA0LTIxVDEwOjMyOjUzWm5leHBlY3RlZFVwZGF0ZcB0MjAyNy0wNC0yNFQxMDozMjo1M1pYQGlLVx7esZatXu10V0UCmuurz9aOoBrC3lzQRzQuhBSKBYNCtboVKCQxMm2g1yh6UUBhk643nLl29KfS-y663_1sZGV2aWNlU2lnbmVkompuYW1lU3BhY2Vz2BhBoGpkZXZpY2VBdXRooW9kZXZpY2VTaWduYXR1cmWEQ6EBJqD2WEAmnROSuZQDvxrnuQEF-MPmlcY8bfR_yGSgTbToApNiZE__YmerxB6o3A317T02iIZt315hBQsHjXv3q7pcAQubZnN0YXR1cwA";
    #[tokio::test]
    async fn verify_vp_works_correctly() {
        let verified_claims = MsoMdocAPI::verify_vp(
            &Presentation {
                value: SAMPLE_MSO_MDOC_VP.to_string(),
                enc_pub_key: None,
            },
            Some(HolderBinder {
                nonce: Nonce::from_secret(
                    "4Y1DVuoVHfjotxmX55AQv36Tr5sdcvaBLXia6bj2hUM".to_string(),
                ),
                verifier_id: "https://embedui.ssi.dev.dsr.gaminghub.bc-labs.dev".to_string(),
            }),
            VerifyOptions {
                trusted_certs_skids: Some(HashSet::from([
                    "5e:21:6b:55:81:6a:9c:5c:0a:78:e7:54:e1:ca:94:0b:72:3e:a1:94".to_string(),
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
            &Claim::String("Mustermann".to_string())
        );
    }
}
