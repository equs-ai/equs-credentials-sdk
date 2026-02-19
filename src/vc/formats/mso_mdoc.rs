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

    // Token may expire as it is fetched from dc_api flow. In order to update it - run dc_api flow and get vp_token. Update nonce & verifier_id if necessary
    pub const SAMPLE_MSO_MDOC_VP: &str = "o2d2ZXJzaW9uYzEuMGZzdGF0dXMAaWRvY3VtZW50c4GjZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbGlzc3VlclNpZ25lZKJqaXNzdWVyQXV0aIRDoQEmoRghWQKPMIICizCCAhGgAwIBAgIQdSXMRkzvVguNEhs9KA1vDjAKBggqhkjOPQQDAzAuMR8wHQYDVQQDDBZPV0YgTXVsdGlwYXogVEVTVCBJQUNBMQswCQYDVQQGDAJVUzAeFw0yNjAyMDUxMjQ3MjBaFw0yNzA1MDYxMjQ3MjBaMCwxHTAbBgNVBAMMFE9XRiBNdWx0aXBheiBURVNUIERTMQswCQYDVQQGDAJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHWNNQt_kg_zsin68YqP0z4EGAQRbhU2NdiYKKW8pjH_GyF0OOifH2AgP6SULLZtXDulq-uv7v9Z2FwgfapfFB2jggERMIIBDTAfBgNVHSMEGDAWgBSrZRvgVsKQU_Hdf2zkh75o3mDJ9TAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjBMBgNVHRIERTBDhkFodHRwczovL2dpdGh1Yi5jb20vb3BlbndhbGxldC1mb3VuZGF0aW9uLWxhYnMvaWRlbnRpdHktY3JlZGVudGlhbDBWBgNVHR8ETzBNMEugSaBHhkVodHRwczovL2dpdGh1Yi5jb20vb3BlbndhbGxldC1mb3VuZGF0aW9uLWxhYnMvaWRlbnRpdHktY3JlZGVudGlhbC9jcmwwHQYDVR0OBBYEFKuHFJaps43ZnActfaein_jVqxPhMAoGCCqGSM49BAMDA2gAMGUCMEuVZSqmsI5W8k6XIB6CETdgBSiwjq0__mo7Wphgxt-UVWRwBRYxEeNPM_dqJuR4ywIxAPyWQkrO9goskd0XaUvwSObnyJeWwppnSLBOHyCoC6gAdh5ViICv9vUVsqeDsACJk1kIZ9gYWQhipmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGx2YWx1ZURpZ2VzdHOicW9yZy5pc28uMTgwMTMuNS4xuCgUWCCndP3NamT49U3cGmsxJQ-NVCBxydDURB51OZuVm34S7RgpWCAaUdOcOQsTGwBJrgQoGiam0g_Zp5ZoX27MNboZ57hKWBghWCCoG-2Z_mDrsCX52Ms_3yRESbqd8J120EftSkBqVIb2RBgnWCBYFMe9vC_ugkCujms5ubBm6VmfKxMimjhP6Cp4FrXHORguWCBHaEkCJWN4tREF-hLdVaiUQSr5Cj6zzcbCAUHZz0DvghgrWCAMsRYKgzPIJkvjNxXfRW_ZwDwsdLXzrOS7Tg6CPjQPyBggWCAFKb8ejmFIbfWuUMXP3f6wTuFAEUfghglZpVa4M9go4xdYIAcK7C83RgMazrX68NoAJ4rAe5U9mwPMvsJRq3JuDDqSEVgg3NIZ3MQ4nd5Nzxt93Qdv2I4km4TI_2hwIOPa99AcsD4YHFgg41UP6wetB6YemaE8c_kW8cp77EPitTZ1UwmfU-AKTFwYKlgggDhVPCAisgGk_1be5hqi6cLNDiNNytntznDgg-Ha-mcYHlggX84FzhQn0EvpcXkYhZWa85hvpLMyRTOcUlmxvtm19hgYI1ggwWHshldHm9akCUk2W_l6KhkdSiZ6Y61Yg0Ff9D_29G4YGFgg7GuwPq7id2lep4tcYsbmP-lglcKgk71eGB0gxzpQ2-0YLVggfdrPatcmHlqmed1IJ2W1ho-PDR0LbneaiWHUPUwsXnIYJFggLuLvnkjWCalnZ_IM715LS-xB5ylVr7hboLXxDDkDSaIVWCByagiFQ6r1ccm2M5p2NWPpu8TOnSmpQOiD3RNDh0Zi7ghYIAFlwnxCdeiFtkVEaOMIjU58vZ2pxe22IjUdBQ06nnyBGB9YIGSfJHkDa8kRmzvY7zq_-ac19XZW-dlQlrMp9jLOcltDC1ggDqKSHjEETVuPETz4N1un4rQBsXk2bMsb3nb75p1AFooYKFggFHD3OSnhitwvSYlDTwO6tXJxqcJgnOMxnPDS2TfMq-cGWCAm720FBrWmk39xwibSAN34nIVL71cl1hmSI6XxrxsF9BgxWCC3Jr7IZWpb_uBERg3erPo6hRItXCwIcOA35EmCs4ZFNg5YIOEqC8Q9OYlGB7ZaZYv-SL1xhA9zWDmJlVReK8El5h2GBFggxaJK83Cmpt7Joe3bvrO-9L7agkz7vvfaNI7Tf_wC6AMFWCCMiaHgYmAFZPqsuRGCbsZlV5kWfm4VjuBcMaWFP0Y0QwNYIFnRUBCbrSpWsUR4GrSGcg6a2fIOApqsdeiS1qrLwtDzEFggca6jpWtxL7Nk_aqC5FD4idz8B6u132bD-BkOXRZhZ70NWCB_V1FQdd8YD5whzSWC5h2ChfoHgimKYndL2LW6W0qk8xgsWCAh7O1bn82PX163iXMhTxNkLheWZxAd_mVr-YYiNxdHJBgvWCDKBeW-Z9ERoi2C_-IE_s3gp2r8eedjQ0yHbKDzMp3s1RgbWCASS7d07pleLb_AjUVrU-eKZWt1cmr4U9LuAVDHmxMSSBgyWCCyPuyoPknR3DZYGAUMPH6WxwMRrvaS5Ogy_uSIu8j-8ABYIJCAWgWdk_RASMyfHbIcrA2s577LFhtkUIKSLU6o-RjLD1ggx5N9P6jyoOYCnCk5D2vjFpPsjH1vXHS6OzKHernkclEYHVggJ-iMnXwxRMruVrt26RwL5djUBBZ_JIc6rq3JjOiNWRQYIlggmFLJU9IunecFbPyRG-kSTzzVVDjQHIlI0kVYdC4mWVsJWCC1-ZXLjnqUzvF9zDBpMFIxxauuBKuk3Dx2TmomRxTXWAFYIN6Af8z8LenEMvzGZd-OQP0nzSKLlj8P6aTAo8Gs9jzyClggAP8vf2JLef1Z1Fw94tnCaN-w2zcQ24WNOm7eE7mdocR3b3JnLmlzby4xODAxMy41LjEuYWFtdmGrDFggQnd6Fi-OjVNxu91ndqcoleC4I4nDLSUm_gdvk22wq1YYGlggicTUcYItAORawAGOjpgEZ7nWBAG5BPyOZ72DoIFJN3wCWCD6LgLb5yzvcXaifFQEFhM_vSB9DtldmOcs9_FcjJEUuhgwWCDbPGIWTKgf6P0oRWYsvpnSovQpilcTrlNsNw2Xy8veKhNYIPoj_18Rlp_RhQ4qvnWxRaYO4lX1hIzkkDDp6kb8nRjJGCZYIKZXxKwBhulE3m2VL-3SMi23i8IN50QgAbc2nh9xvdxdElggqDBqKmofeyRQISlti8bfid23aWO_bgeLWpRmePAzg-MHWCDfBf4T0tgJ_zvhKsW2QNwtvoDcAJSkNvhCVJUm0EmTrBgZWCDV-UQUTl1GEabX1kHs6MjivEG8h71gXpfNhdo3lQ38hRZYIIoREVou9EU8XXOP174OMq8OX9PhosjdXbNyeirBUo_RGCVYIHH-54_J9d2mzUOszD4oxoJZito94OIeH29tOiZE147-bWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggh2piuvI1kF8yP58fW5SyR54sCJuASH5Pwvv_Ui8NzeoiWCDYDEOC5Jr6PvNdxi8747E4XbNemDQF40nfhWsXjNzfQWx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNi0wMi0wNlQxMTo0NzoyMFppdmFsaWRGcm9twHQyMDI2LTAyLTA2VDExOjQ3OjIwWmp2YWxpZFVudGlswHQyMDI3LTAyLTA2VDEyOjQ3OjIwWlhAPtm4oFRHAjBPdoqXy_CG3m6x_BS2EdAtBoY5-a3iNMpJilt7uMHd2qMDGQ-fQ8cntUngxAQZdmTt9tA3KOR2vWpuYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYLYGFhUpGhkaWdlc3RJRBgpZnJhbmRvbVDS0sD2d_Seod35eiNNpdZbcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZUVyaWth2BhYWaRoZGlnZXN0SUQUZnJhbmRvbVBn1X031j5CAXqfnYhnKMgucWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWpNdXN0ZXJtYW5ubGRldmljZVNpZ25lZKJqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAyl6oHsc01u-eSsCJkTv8aDmSeTdf8lonxc4RUvdbUwLbFZgaOTydtLjTf5JnFDX35IqQmZkJqzZsKVeWat7NMmpuYW1lU3BhY2Vz2BhBoA";
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
                    "AB:65:1B:E0:56:C2:90:53:F1:DD:7F:6C:E4:87:BE:68:DE:60:C9:F5".to_lowercase(),
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
