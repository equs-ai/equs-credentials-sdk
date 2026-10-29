use crate::crypto::{JWK, Key, Signer};
use crate::did::universal::UniversalResolver;
use crate::utils::certificate_validator::SharedCertificateValidator;
use crate::vc::HasClaims;
use crate::vc::claims::{Claim, Claims};
use crate::vc::core::{HolderBinder, PresentationRestrictionValue};
use crate::vc::formats::{
    API, AnchorPolicy, HasCredential, JsonSnafu, UnimplementedSnafu, VerifyOptions,
};
use crate::vc::formats::{PresentationSnafu, Result};
use async_trait::async_trait;
use one_core::config::core_config::{KeyAlgorithmType, VerificationProtocolType};
use one_core::model::did::KeyRole;
use one_core::proto::certificate_validator::CertificateValidator;
use one_core::proto::key_verification::KeyVerification;
use one_core::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use one_core::provider::credential_formatter::model::{
    CredentialClaimValue, CredentialStatus, DetailCredential, IdentifierDetails,
};
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
use one_core_portable::standardized_types::jwk::PublicJwk;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use ssi::dids::DIDURL;
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::Level;
use tracing::{info, instrument, warn};

pub(crate) const DOCTYPE_CLAIM: &str = "doctype";
const TOKEN_STATUS_LIST_ENTRY: &str = "TokenStatusListEntry";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MdocStatus {
    None,
    StatusList { uri: String, idx: usize },
    Unsupported(Vec<String>),
}

#[derive(Debug)]
pub(crate) struct VerifiedMdoc {
    pub claims: Claims,
    pub issuer_chain: Option<String>,
    pub status: MdocStatus,
}

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
        Self::verify_vp_with_issuer(presentation, holder_binder, opts, did_resolver)
            .await
            .map(|verified| verified.claims)
    }
}

impl MsoMdocAPI {
    /// [API::verify_vp], also returning the issuer certificate chain and the MSO status. Only the
    /// first document of the DeviceResponse is returned.
    pub(crate) async fn verify_vp_with_issuer(
        presentation: &Presentation,
        holder_binder: Option<HolderBinder>,
        opts: VerifyOptions,
        did_resolver: UniversalResolver,
    ) -> Result<VerifiedMdoc> {
        let anchor_policy = opts.anchor_policy;
        let certificate_validator: Arc<dyn CertificateValidator> =
            Arc::new(SharedCertificateValidator::get());

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
        let response_uri = holder_binder.as_ref().and_then(|b| b.response_uri.clone());
        let ctx = ExtractPresentationCtx {
            verification_protocol_type: VerificationProtocolType::OpenId4VpFinal1_0,
            nonce: holder_binder.clone().map(|b| b.nonce.secret().to_string()),
            client_id: holder_binder.map(|b| b.origin_or_verifier_id().to_owned()),
            // integrity-only: one-core validates the issuer chain without an anchor; the caller
            // evaluates issuer trust
            trusted_certs: match opts.anchor_policy {
                AnchorPolicy::Require => opts.trusted_certs.filter(|certs| !certs.is_empty()),
                AnchorPolicy::IntegrityOnly => None,
            },
            verifier_key,
            format_nonce: None,
            issuance_date: None,
            expiration_date: None,
            mdoc_session_transcript: None,
            response_uri,
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

        if extracted_vps.credentials.len() > 1 {
            warn!(
                documents = extracted_vps.credentials.len(),
                "Checking issuer trust and status of the first mdoc document only"
            );
        }
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

        let issuer_chain = match &verified_claims.issuer {
            IdentifierDetails::Certificate(certificate) => Some(certificate.chain.clone()),
            _ => None,
        };
        // one-core does not reject a self-signed leaf without anchors
        if let (AnchorPolicy::IntegrityOnly, Some(chain)) = (anchor_policy, issuer_chain.as_deref())
        {
            crate::utils::x509_truststore::verify_chain_integrity(
                certificate_validator.as_ref(),
                chain,
            )
            .await
            .map_err(|details| {
                PresentationSnafu {
                    details: format!("Issuer certificate chain is not valid: {details}"),
                }
                .build()
            })?;
        }
        let status = MdocStatus::from_credential_status(&verified_claims.status)?;
        Ok(VerifiedMdoc {
            claims: verified_claims.try_into()?,
            issuer_chain,
            status,
        })
    }

    /// The MSO status of the first document, read without verifying the presentation.
    pub(crate) async fn status_unverified(presentation: &Presentation) -> Result<MdocStatus> {
        let certificate_validator = SharedCertificateValidator::get();
        let ctx = ExtractPresentationCtx {
            verification_protocol_type: VerificationProtocolType::OpenId4VpFinal1_0,
            nonce: None,
            client_id: None,
            trusted_certs: None,
            verifier_key: None,
            format_nonce: None,
            issuance_date: None,
            expiration_date: None,
            mdoc_session_transcript: None,
            response_uri: None,
        };
        let extracted =
            MsoMdocPresentationFormatter::new(Arc::new(certificate_validator.clone()), None)
                .extract_presentation_unverified(presentation.value.as_str(), ctx)
                .await
                .map_err(|e| {
                    PresentationSnafu {
                        details: format!("Failed to read mso_mdoc presentation: {e}"),
                    }
                    .build()
                })?;
        let credential = extracted.credentials.first().ok_or_else(|| {
            PresentationSnafu {
                details: "mso_mdoc presentation holds no document".to_string(),
            }
            .build()
        })?;
        let details = MdocFormatter::extract_credentials(&certificate_validator, credential, false)
            .await
            .map_err(|e| {
                PresentationSnafu {
                    details: format!("Failed to read mso_mdoc credential: {e}"),
                }
                .build()
            })?;
        MdocStatus::from_credential_status(&details.status)
    }
}

impl MdocStatus {
    fn from_credential_status(entries: &[CredentialStatus]) -> Result<Self> {
        if entries.is_empty() {
            return Ok(Self::None);
        }
        let (status_lists, others): (Vec<_>, Vec<_>) = entries
            .iter()
            .partition(|entry| entry.r#type == TOKEN_STATUS_LIST_ENTRY);
        let others: Vec<String> = others.iter().map(|entry| entry.r#type.clone()).collect();
        let Some(status_list) = status_lists.first() else {
            return Ok(Self::Unsupported(others));
        };
        if !others.is_empty() {
            info!(mechanisms = ?others, "mdoc status mechanisms other than status_list not checked");
        }

        let field = |name: &str| {
            status_list
                .additional_fields
                .get(name)
                .and_then(serde_json::Value::as_str)
        };
        match (field("uri"), field("idx").and_then(|idx| idx.parse().ok())) {
            (Some(uri), Some(idx)) => Ok(Self::StatusList {
                uri: uri.to_string(),
                idx,
            }),
            _ => PresentationSnafu {
                details: "Malformed mso_mdoc status_list".to_string(),
            }
            .fail(),
        }
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
    use crate::utils::test_utils::{anchors, mdl_chain, mdl_iaca};
    use crate::vc::VCFormatsAPI;
    use crate::vc::claims::Claim;
    use crate::vc::core::HolderBinder;
    use crate::vc::formats::mso_mdoc::{MsoMdocAPI, Presentation, VerifiedMdoc};
    use crate::vc::formats::{AnchorPolicy, VerifyOptions};
    use std::collections::HashMap;

    pub const NONCE: &str = "4Y1DVuoVHfjotxmX55AQv36Tr5sdcvaBLXia6bj2hUM";
    pub const VERIFIER: &str = "https://verifier.example.com";
    const RESPONSE_URI: &str = "https://verifier.example.com/response";

    /// mDL presentation under a fresh IACA → DS chain, bound to `NONCE` and `VERIFIER`.
    pub fn sample_mso_mdoc_vp() -> String {
        mdoc_vp(None, None)
    }

    #[tokio::test]
    async fn verify_vp_works_correctly() {
        let verified_claims = MsoMdocAPI::verify_vp(
            &Presentation {
                value: sample_mso_mdoc_vp(),
                enc_pub_key: None,
            },
            Some(binder(None)),
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
            &Claim::String("Mustermann".to_string())
        );
    }

    #[tokio::test]
    #[should_panic(expected = "Issuer certificate chain is not trusted")]
    async fn verify_vp_rejects_ds_chain_not_under_held_iaca() {
        MsoMdocAPI::verify_vp(
            &Presentation {
                value: sample_mso_mdoc_vp(),
                enc_pub_key: None,
            },
            Some(binder(None)),
            VerifyOptions {
                trusted_certs: Some(unrelated_iaca()),
                selective_claims: None,
                anchor_policy: Default::default(),
            },
            UniversalResolver::default(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "verifying DeviceSigned")]
    async fn verify_vp_rejects_mismatched_nonce() {
        MsoMdocAPI::verify_vp(
            &Presentation {
                value: sample_mso_mdoc_vp(),
                enc_pub_key: None,
            },
            Some(HolderBinder {
                nonce: Nonce::from_secret("another-nonce".to_string()),
                ..binder(None)
            }),
            VerifyOptions::default(),
            UniversalResolver::default(),
        )
        .await
        .unwrap();
    }

    #[rstest::rstest]
    #[case::matching_response_uri(Some(RESPONSE_URI), true)]
    #[case::other_response_uri(Some("https://verifier.example.com/other"), false)]
    #[case::no_response_uri(None, false)]
    #[tokio::test]
    async fn verify_vp_binds_the_response_uri(
        #[case] response_uri: Option<&str>,
        #[case] valid: bool,
    ) {
        let result = MsoMdocAPI::verify_vp(
            &Presentation {
                value: mdoc_vp(Some(RESPONSE_URI), None),
                enc_pub_key: None,
            },
            Some(binder(response_uri)),
            VerifyOptions::default(),
            UniversalResolver::default(),
        )
        .await;

        assert_binding(result, valid);
    }

    #[rstest::rstest]
    #[case::matching_key(Some(test_fixtures::keys().verifier.to_public()), true)]
    #[case::no_key(None, false)]
    #[case::other_key(Some(test_fixtures::keys().issuer.to_public()), false)]
    #[tokio::test]
    async fn verify_vp_binds_the_verifier_key(
        #[case] enc_pub_key: Option<test_fixtures::JWK>,
        #[case] valid: bool,
    ) {
        let result = MsoMdocAPI::verify_vp(
            &Presentation {
                value: mdoc_vp(Some(RESPONSE_URI), Some(&test_fixtures::keys().verifier)),
                enc_pub_key,
            },
            Some(binder(Some(RESPONSE_URI))),
            VerifyOptions::default(),
            UniversalResolver::default(),
        )
        .await;

        assert_binding(result, valid);
    }

    #[tokio::test]
    async fn integrity_only_rejects_a_self_signed_document_signer() {
        let ds_key = test_fixtures::JWK::generate_p256();
        let self_signed_ds = test_fixtures::x509(
            &serde_json::json!({
                "subject": [["CN", "Self-signed DS"], ["C", "US"]],
                "not_before": "2026-01-01", "not_after": "2046-01-01",
                "key_usages": ["digital_signature"]
            }),
            &ds_key,
            None,
        );

        let result =
            verify_integrity_only(mdoc_vp_under(&self_signed_ds, &ds_key, None, None, None)).await;

        let error = format!("{:?}", result.expect_err("a self-signed DS must fail"));
        assert!(
            error.contains("the leaf certificate is self-signed"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn integrity_only_accepts_a_document_signer_issued_by_an_iaca() {
        let verified = verify_integrity_only(sample_mso_mdoc_vp()).await.unwrap();

        assert!(verified.issuer_chain.is_some());
    }

    async fn verify_integrity_only(vp: String) -> crate::vc::formats::Result<VerifiedMdoc> {
        MsoMdocAPI::verify_vp_with_issuer(
            &Presentation {
                value: vp,
                enc_pub_key: None,
            },
            Some(binder(None)),
            VerifyOptions {
                trusted_certs: None,
                selective_claims: None,
                anchor_policy: AnchorPolicy::IntegrityOnly,
            },
            UniversalResolver::default(),
        )
        .await
    }

    /// [sample_mso_mdoc_vp] together with the IACA (PEM) that issued its Document Signer.
    pub fn sample_mso_mdoc_vp_with_iaca() -> (String, String) {
        mdoc_vp_with_iaca(None, None)
    }

    fn mdoc_vp(response_uri: Option<&str>, verifier_key: Option<&test_fixtures::JWK>) -> String {
        mdoc_vp_with_iaca(response_uri, verifier_key).0
    }

    fn mdoc_vp_with_iaca(
        response_uri: Option<&str>,
        verifier_key: Option<&test_fixtures::JWK>,
    ) -> (String, String) {
        mdoc_vp_from(response_uri, verifier_key, None)
    }

    /// [sample_mso_mdoc_vp_with_iaca] whose MSO carries `status`.
    pub fn sample_mso_mdoc_vp_with_status(status: serde_json::Value) -> (String, String) {
        mdoc_vp_from(None, None, Some(status))
    }

    /// The [HolderBinder] the sample presentations are bound to.
    pub fn sample_binder() -> HolderBinder {
        binder(None)
    }

    fn mdoc_vp_from(
        response_uri: Option<&str>,
        verifier_key: Option<&test_fixtures::JWK>,
        status: Option<serde_json::Value>,
    ) -> (String, String) {
        let (iaca, ds, ds_key) = mdl_chain();
        let vp = mdoc_vp_under(&ds, &ds_key, response_uri, verifier_key, status);
        (vp, iaca)
    }

    /// A presentation signed by `ds_key` under `x5chain`.
    fn mdoc_vp_under(
        x5chain: &str,
        ds_key: &test_fixtures::JWK,
        response_uri: Option<&str>,
        verifier_key: Option<&test_fixtures::JWK>,
        status: Option<serde_json::Value>,
    ) -> String {
        test_fixtures::mdoc(
            &serde_json::json!({
                "doc_type": "org.iso.18013.5.1.mDL",
                "name_spaces": { "org.iso.18013.5.1": {
                    "family_name": "Mustermann", "given_name": "Erika"
                } },
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2046-01-01T00:00:00Z",
                "x5chain": x5chain,
                "client_id": VERIFIER,
                "nonce": NONCE,
                "response_uri": response_uri,
                "verifier_key": verifier_key.map(test_fixtures::JWK::to_public),
                "status": status
            }),
            ds_key,
            &test_fixtures::keys().holder,
        )
    }

    /// Ok, or the DeviceSigned failure of a wrong binding.
    fn assert_binding<T: std::fmt::Debug, E: std::fmt::Debug>(result: Result<T, E>, valid: bool) {
        match result {
            Ok(_) if valid => {}
            Err(err) if !valid => assert!(
                format!("{err:?}").contains("verifying DeviceSigned"),
                "{err:?}"
            ),
            result => panic!("expected valid = {valid}, got {result:?}"),
        }
    }

    fn binder(response_uri: Option<&str>) -> HolderBinder {
        HolderBinder {
            nonce: Nonce::from_secret(NONCE.to_string()),
            verifier_id: VERIFIER.to_string(),
            response_uri: response_uri.map(str::to_string),
        }
    }

    /// Anchors holding only an unrelated IACA.
    fn unrelated_iaca() -> HashMap<String, String> {
        anchors(&[&mdl_iaca(&test_fixtures::JWK::generate_p256())])
    }
}
