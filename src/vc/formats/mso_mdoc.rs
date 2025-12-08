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

    pub const SAMPLE_MSO_MDOC_VP: &str = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWFSkaGRpZ2VzdElEAGZyYW5kb21Q7lVYU32ol-5va1L4AWunv3FlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVlU21pdGjYGFhRpGhkaWdlc3RJRAFmcmFuZG9tUPz9gTn3yJkJ7I6BpBE6cJ5xZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVjSm9uamlzc3VlckF1dGiEQ6EBJqEYIVkCxDCCAsAwggJnoAMCAQICFB5_GzKtTzTv5LDMB7ew4zOnCxhNMAoGCCqGSM49BAMCMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKDBNEaWdpdGFsIENyZWRlbnRpYWxzMR8wHQYDVQQDDBZkaWdpdGFsY3JlZGVudGlhbHMuZGV2MB4XDTI1MDIxOTIzMzAxOFoXDTI2MDIxOTIzMzAxOFoweTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxHDAaBgNVBAoME0RpZ2l0YWwgQ3JlZGVudGlhbHMxHzAdBgNVBAMMFmRpZ2l0YWxjcmVkZW50aWFscy5kZXYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATreTYr4tfzl8NQBH2D4eNiLONVazYPamjHWLsN3Gr4bAmvml1dDZk5dhLDWieRlpjKAA_IpMABbM2ISHjYBeNpo4HMMIHJMB8GA1UdIwQYMBaAFKJP9InZfEbobqOG2UdIzsy-3M_1MB0GA1UdDgQWBBTf_mpaEunAYsS8mKcl0tlw93pgKDA0BgNVHR8ELTArMCmgJ6AlhiNodHRwczovL2RpZ2l0YWwtY3JlZGVudGlhbHMuZGV2L2NybDAqBgNVHRIEIzAhhh9odHRwczovL2RpZ2l0YWwtY3JlZGVudGlhbHMuZGV2MA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAoGCCqGSM49BAMCA0cAMEQCIGHFy_V8weN78uCxM9ofIDEEXXCbWiEUDnpoMJvLB0LnAiBwr6LhxJv7p4wVzAnlGe0Ef8pqYxshyE8NufwfR_ULAlkDpNgYWQOfpmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xsQBYILdEs7_XA0rH0oVmG4e_1-Q9OSQoVWPf4WxAb3bargetAVggxvkuQ7ziHlnVON81jim4j4vpUoTgRORvU9eCQ-zz9WQCWCDuGoKUm0v7jW76Jm1Vn94SMSUyIVjmLX1ElSki5g4grANYIAnY_0LLgT_pZBWWgJn_7SDetRH4BNesidk8sUgBMObLBFggjqk0iKzv_rb9MuntCGncrmcffojw4HWLBbXMZlyjLvYFWCAItAs1Sxa4P48BX7QyEM5Z419Elb0OWyFJZLyVpyzUvwZYIJmOmZFzaQhA_nKLF5L5mxtkLr15A2S8k_tXyX4_zJ8hB1ggOZRkJD-1UBF5FmUBO_N6QkVkPZwLsW9EOhUsguygv-sIWCAjN0yxgouVkGuaPMkMGDTLCqu44-ONPT5O-4rSHbPeMQlYIO3mzAJ437LcOtk_JJhUMY9gBUn-dxTlkKUdho25W9QEClggGF_FH_u3eTNstsq_Wxo7aUrNfCKG75sJu1rQFcGmO5ILWCBkgjc9Dzc_PHk3yHpTqllj7XqBRij_6OYmU_8vkOI6hgxYIJKdydleP5DesrXsrb7qouaOIAhqy1Gf0rQI8qaCQgclDVggtUWG3sibdrwgt1YnbRnh4mvo9MFTjXDqBMWu9Et51-4OWCDQBtrDMPMB1Yejrtm6Pvq60eK7X6gQVByyfB8KzSXp1A9YIH-HNSZICcE4jXRd3R0h2M4QVLRdmtRuqsYi3QMQbvrxEFggfsAfLJE7d3ZlU4GHebWB5HxaZoerHxQwnqjeMAziVY9tZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCBOeV4BXAO8q-MQP9OHz0N3ndZpF14FssUxNSAHslh5-CJYIPEGkN2tVGwEqGue87-TRoRGdi6ExCuRW9wD5YVGMDAsbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHgbMjAyNS0xMS0wNVQxMToyMzo1Ni40NDY4ODhaaXZhbGlkRnJvbcB4GzIwMjUtMTEtMDVUMTE6MjM6NTYuNDQ3MDQ4Wmp2YWxpZFVudGlswHgbMjAzNS0xMC0yNFQxMToyMzo1Ni40NDcwNDhaWEC_wgicTZValZ50GYfCkLkEjqSsCCJ5cArXSefssDjyx54Ak8LMjfQoDvrRN_ecSmZKEtwDOOSSXXSaeyvc0Q8NbGRldmljZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAUwIrCKEYJQdnyaqbtOrTj5TO1bv3IF7UuwvLFD9-v3jKt0GDs_c6uE_n5gFy_qNYoKsPGG4SXq_YwbwXQX2u3WZzdGF0dXMA";
    #[tokio::test]
    async fn verify_vp_works_correctly() {
        let verified_claims = MsoMdocAPI::verify_vp(
            &Presentation {
                value: SAMPLE_MSO_MDOC_VP.to_string(),
                enc_pub_key: None,
            },
            Some(HolderBinder {
                nonce: Nonce::from_secret(
                    "LFlqUm26sHqEgTaBQMuHPkrEuHyKYvXowI7Ge3LPV4o".to_string(),
                ),
                verifier_id: "https://digital-credentials.dev".to_string(),
            }),
            VerifyOptions::default(),
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
            &Claim::String("Smith".to_string())
        );
    }
}
