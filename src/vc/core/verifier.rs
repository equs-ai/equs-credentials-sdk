use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::vc::claims::Claims;
#[cfg(feature = "delegate-sd-jwt")]
use crate::vc::claims::{DELEGATIONS_CLAIM, ISSUED_VC_CLAIM};
use crate::vc::core::Result;
use crate::vc::core::api::{
    CredentialExpiredSnafu, ExpirationCheckSnafu, ParseSnafu, VCNotValidSnafu,
};
use crate::vc::core::{
    ClaimsSnafu, CredentialStatusNotSupportedSnafu, FormatNotSupportedSnafu, HolderBinder,
    IssuerNotTrustedSnafu, VCSnafu, VCStatusSnafu, Verifier,
};
#[cfg(feature = "delegate-sd-jwt")]
use crate::vc::formats::dsd_jwt::{DsdJwtAPI, DsdJwtPurpose};
use crate::vc::formats::json_ld_vc::JsonLdAPI;
use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
use crate::vc::formats::{API, AnchorPolicy, HasCredential, IsExpired, VerifyOptions};
use crate::vc::status_formats::status_list_token_jwt;
use crate::vc::status_formats::status_list_token_jwt::StatusListJwt;
use crate::vc::trust::issuer::{
    IssuerTrustConfig, IssuerTrustMode, IssuerTrustOutcome, IssuerTrustVerification, TrustAnchor,
};
use crate::vc::{HasClaims, Presentation};
use crate::vc::{HasVPFormat, VCStatus};
use async_trait::async_trait;
#[cfg(feature = "delegate-sd-jwt")]
use serde_json::Value;
use snafu::ResultExt;
use std::collections::HashMap;
use std::convert::TryFrom;
use tracing::{Level, info, instrument};

#[derive(Debug, Default, Clone)]
pub struct VerificationParams {
    // PEM of each trusted x509 anchor, keyed by its Subject Key Identifier (SKI).
    pub trusted_certs: Option<HashMap<String, String>>,
    /// Issuer-trust anchors and mode for [Verifier::verify_presentation]. When
    /// unset, `trusted_certs` are used as anchors in [IssuerTrustMode::Enforce].
    pub issuer_trust: Option<IssuerTrustConfig>,
}

#[derive(Clone)]
pub struct VerifierService {
    verifier_id: String,
    did_resolver: UniversalResolver,
    verification_params: VerificationParams,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Verifier for VerifierService {
    #[instrument(level = Level::TRACE, skip_all, err())]
    async fn verify_presentation(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation: &Presentation,
        http_client: &dyn HttpClient,
    ) -> Result<IssuerTrustVerification> {
        #[cfg(target_arch = "wasm32")]
        let verified = {
            // wasm has no `x5c` or mdoc issuer chain
            let claims = self
                .verify_claims(holder_binder, presentation, http_client)
                .await?;
            let category = self
                .issuer_trust_config()
                .classification
                .classify_claims(&claims);
            IssuerTrustVerification::without_chain(
                claims,
                IssuerTrustOutcome::without_chain(category),
            )
        };
        #[cfg(not(target_arch = "wasm32"))]
        let verified = self
            .verify_with_issuer_trust(holder_binder, presentation, http_client)
            .await?;

        self.enforce_issuer_trust(verified)
    }

    #[cfg(feature = "delegate-sd-jwt")]
    #[instrument(level = Level::TRACE, skip_all, err())]
    async fn verify_delegation(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation: &Presentation,
        http_client: &dyn HttpClient,
    ) -> Result<IssuerTrustVerification> {
        let Presentation::SdJwtVp(vp) = presentation else {
            return FormatNotSupportedSnafu {
                format: presentation.format().to_string(),
            }
            .fail();
        };

        let view = DsdJwtAPI::verify_dsd_jwt(
            vp,
            self.did_resolver.clone(),
            DsdJwtPurpose::Delegation(holder_binder),
        )
        .await
        .context(VCSnafu)?;

        let issued_vc = Claims::try_from(view.verified_claims).context(ClaimsSnafu)?;
        // a grant's issued credential is signed through a DID
        let category = self
            .issuer_trust_config()
            .classification
            .classify_claims(&issued_vc);

        let delegations = Value::Array(
            view.delegate_payloads
                .into_iter()
                .map(|hop| Value::Array(hop.into_iter().map(Value::Object).collect()))
                .collect(),
        );
        let mut claims = Claims::new();
        claims.insert(ISSUED_VC_CLAIM.to_string(), issued_vc.clone().into());
        claims.insert(DELEGATIONS_CLAIM.to_string(), delegations.into());

        let verified = self.enforce_issuer_trust(IssuerTrustVerification::without_chain(
            claims,
            IssuerTrustOutcome::without_chain(category),
        ))?;
        self.check_sd_jwt_expiry_and_status(&issued_vc, vp, http_client, AnchorPolicy::Require)
            .await?;
        Ok(verified)
    }

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    async fn obtain_credential_status(
        &self,
        presentation: &Presentation,
        http_client: &dyn HttpClient,
    ) -> Result<Option<VCStatus>> {
        match presentation {
            Presentation::SdJwtVp(vp) => {
                self.obtain_sd_jwt_vc_status(vp, http_client, AnchorPolicy::Require)
                    .await
            }
            #[cfg(not(target_arch = "wasm32"))]
            Presentation::MsoMdoc(vp) => {
                use crate::vc::formats::mso_mdoc::MsoMdocAPI;

                let status = MsoMdocAPI::status_unverified(vp).await.context(VCSnafu)?;
                self.obtain_mdoc_status(&status, http_client, AnchorPolicy::Require)
                    .await
            }
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
            verification_params: Default::default(),
        }
    }

    #[instrument(level = Level::TRACE, skip(self))]
    pub fn with_verification_params(mut self, opts: VerificationParams) -> Self {
        self.verification_params = opts;
        self
    }

    #[instrument(level = Level::TRACE, skip_all, err())]
    /// Verifies against `trusted_certs`, without evaluating issuer trust.
    async fn verify_claims(
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
                        trusted_certs: self.verification_params.trusted_certs.clone(),
                        selective_claims: None,
                        anchor_policy: AnchorPolicy::Require,
                    },
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;

                self.check_sd_jwt_expiry_and_status(
                    &claims,
                    vp,
                    http_client,
                    AnchorPolicy::Require,
                )
                .await?;

                claims
            }
            Presentation::LdpVp(vp) => {
                JsonLdAPI::verify_vp(
                    vp,
                    holder_binder,
                    Default::default(),
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

                let verified = MsoMdocAPI::verify_vp_with_issuer(
                    vp,
                    holder_binder,
                    VerifyOptions {
                        trusted_certs: self.verification_params.trusted_certs.clone(),
                        selective_claims: None,
                        anchor_policy: AnchorPolicy::Require,
                    },
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;
                self.check_mdoc_status(&verified.status, http_client, AnchorPolicy::Require)
                    .await?;

                verified.claims
            }
            _ => FormatNotSupportedSnafu {
                format: presentation.format().to_string(),
            }
            .fail()?,
        };

        Ok(cred_claims)
    }

    fn enforce_issuer_trust(
        &self,
        verified: IssuerTrustVerification,
    ) -> Result<IssuerTrustVerification> {
        if self.issuer_trust_config().mode == IssuerTrustMode::Enforce
            && verified.outcome.rejected_when_enforced()
        {
            return IssuerNotTrustedSnafu {
                verified: Box::new(verified),
            }
            .fail();
        }
        Ok(verified)
    }

    fn issuer_trust_config(&self) -> IssuerTrustConfig {
        self.verification_params
            .issuer_trust
            .clone()
            .unwrap_or_else(|| IssuerTrustConfig {
                mode: IssuerTrustMode::Enforce,
                anchors: self
                    .verification_params
                    .trusted_certs
                    .iter()
                    .flat_map(|certs| certs.values())
                    .map(TrustAnchor::new)
                    .collect(),
                ..Default::default()
            })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn issuer_anchors_by_ski(&self, anchors: &[TrustAnchor]) -> Option<HashMap<String, String>> {
        let only_non_issuing = |pem: &str| {
            let mut same = anchors.iter().filter(|anchor| anchor.pem == pem).peekable();
            same.peek().is_some() && same.all(|anchor| !anchor.anchors_issuers())
        };
        self.verification_params
            .trusted_certs
            .as_ref()
            .map(|certs| {
                certs
                    .iter()
                    .filter(|(_, pem)| !only_non_issuing(pem))
                    .map(|(ski, pem)| (ski.clone(), pem.clone()))
                    .collect()
            })
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(level = Level::TRACE, skip_all, err())]
    async fn verify_with_issuer_trust(
        &self,
        holder_binder: Option<HolderBinder>,
        presentation: &Presentation,
        http_client: &dyn HttpClient,
    ) -> Result<IssuerTrustVerification> {
        use crate::utils::certificate_validator::SharedCertificateValidator;
        use crate::vc::formats::mso_mdoc::MsoMdocAPI;
        use crate::vc::trust::issuer::{
            SdJwtIssuerKey, evaluate_chain_for_category, sd_jwt_issuer_key,
        };
        use crate::vc::trust::trusted_authorities::chain_authority_key_identifiers;

        let config = self.issuer_trust_config();
        let certificate_validator = SharedCertificateValidator::get();
        let anchors_by_ski = self.issuer_anchors_by_ski(&config.anchors);
        let integrity_only = VerifyOptions {
            trusted_certs: anchors_by_ski,
            selective_claims: None,
            anchor_policy: AnchorPolicy::IntegrityOnly,
        };

        match presentation {
            Presentation::SdJwtVp(vp) => {
                let claims = SdJwtAPI::verify_vp(
                    vp,
                    holder_binder,
                    integrity_only,
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;

                let category = config.classification.classify_claims(&claims);
                let (outcome, issuer_chain_akis) = match sd_jwt_issuer_key(vp).context(VCSnafu)? {
                    SdJwtIssuerKey::X5c(chain) => (
                        evaluate_chain_for_category(
                            &certificate_validator,
                            &chain,
                            &config,
                            category,
                        )
                        .await
                        .map_err(rejected_issuer_chain)
                        .context(VCSnafu)?,
                        Some(chain_authority_key_identifiers(&chain)),
                    ),
                    SdJwtIssuerKey::Other => (IssuerTrustOutcome::without_chain(category), None),
                };

                if let Some(policy) = status_anchor_policy(config.mode, &outcome) {
                    self.check_sd_jwt_expiry_and_status(&claims, vp, http_client, policy)
                        .await?;
                }
                Ok(IssuerTrustVerification::new(
                    claims,
                    outcome,
                    issuer_chain_akis,
                ))
            }
            Presentation::MsoMdoc(vp) => {
                let verified = MsoMdocAPI::verify_vp_with_issuer(
                    vp,
                    holder_binder,
                    integrity_only,
                    self.did_resolver.clone(),
                )
                .await
                .context(VCSnafu)?;
                let category = config.classification.classify_claims(&verified.claims);
                let (outcome, issuer_chain_akis) = match verified.issuer_chain {
                    Some(chain) => (
                        evaluate_chain_for_category(
                            &certificate_validator,
                            &chain,
                            &config,
                            category,
                        )
                        .await
                        .map_err(rejected_issuer_chain)
                        .context(VCSnafu)?,
                        Some(chain_authority_key_identifiers(&chain)),
                    ),
                    None => (IssuerTrustOutcome::without_chain(category), None),
                };

                if let Some(policy) = status_anchor_policy(config.mode, &outcome) {
                    self.check_mdoc_status(&verified.status, http_client, policy)
                        .await?;
                }
                Ok(IssuerTrustVerification::new(
                    verified.claims,
                    outcome,
                    issuer_chain_akis,
                ))
            }
            _ => {
                let claims = self
                    .verify_claims(holder_binder, presentation, http_client)
                    .await?;
                let category = config.classification.classify_claims(&claims);
                Ok(IssuerTrustVerification::without_chain(
                    claims,
                    IssuerTrustOutcome::without_chain(category),
                ))
            }
        }
    }

    #[instrument(level = Level::TRACE, skip_all, err())]
    async fn check_sd_jwt_expiry_and_status(
        &self,
        claims: &Claims,
        presentation: &crate::vc::formats::sd_jwt_vc::Presentation,
        http_client: &dyn HttpClient,
        anchor_policy: AnchorPolicy,
    ) -> Result<()> {
        if SdJwtAPI::is_expired(claims).context(ExpirationCheckSnafu)? {
            CredentialExpiredSnafu.fail()?
        };

        ensure_valid(
            self.obtain_sd_jwt_vc_status(presentation, http_client, anchor_policy)
                .await?,
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(level = Level::TRACE, skip(self, status, http_client), err())]
    async fn check_mdoc_status(
        &self,
        status: &crate::vc::formats::mso_mdoc::MdocStatus,
        http_client: &dyn HttpClient,
        anchor_policy: AnchorPolicy,
    ) -> Result<()> {
        ensure_valid(
            self.obtain_mdoc_status(status, http_client, anchor_policy)
                .await?,
        )
    }

    /// The status of an mdoc's MSO `status_list` entry; any other declared mechanism fails.
    #[cfg(not(target_arch = "wasm32"))]
    #[instrument(level = Level::TRACE, skip(self, status, http_client), err(), ret())]
    async fn obtain_mdoc_status(
        &self,
        status: &crate::vc::formats::mso_mdoc::MdocStatus,
        http_client: &dyn HttpClient,
        anchor_policy: AnchorPolicy,
    ) -> Result<Option<VCStatus>> {
        use crate::vc::formats::mso_mdoc::MdocStatus;

        match status {
            MdocStatus::None => Ok(None),
            MdocStatus::Unsupported(mechanisms) => VCStatusSnafu {
                details: format!("status mechanism not supported: {}", mechanisms.join(", ")),
            }
            .fail(),
            MdocStatus::StatusList { uri, idx } => StatusListJwt::get_status_list_entry(
                uri,
                *idx,
                http_client,
                self.did_resolver.clone(),
                None,
                self.verification_params.trusted_certs.as_ref(),
                anchor_policy,
            )
            .await
            .map(|status| Some(VCStatus::StatusListToken(status)))
            .map_err(|e| {
                VCStatusSnafu {
                    details: e.to_string(),
                }
                .build()
            }),
        }
    }

    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    async fn obtain_sd_jwt_vc_status(
        &self,
        presentation: &crate::vc::formats::sd_jwt_vc::Presentation,
        http_client: &dyn HttpClient,
        anchor_policy: AnchorPolicy,
    ) -> Result<Option<VCStatus>> {
        let claims = presentation.parse_claims().context(VCSnafu)?;

        let status = StatusListJwt::get_vc_status_with_trusted_certs(
            &claims,
            http_client,
            self.did_resolver.clone(),
            None,
            self.verification_params.trusted_certs.as_ref(),
            anchor_policy,
        )
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

fn ensure_valid(status: Option<VCStatus>) -> Result<()> {
    match status {
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

    Ok(())
}

/// How the status list signer is checked: anchored for a trusted issuer and under `Enforce`,
/// integrity-only for an untrusted issuer under `Report`, skipped once `Enforce` rejected it.
#[cfg(not(target_arch = "wasm32"))]
fn status_anchor_policy(
    mode: IssuerTrustMode,
    outcome: &IssuerTrustOutcome,
) -> Option<AnchorPolicy> {
    match mode {
        IssuerTrustMode::Enforce if outcome.rejected_when_enforced() => None,
        IssuerTrustMode::Enforce => Some(AnchorPolicy::Require),
        IssuerTrustMode::Report
            if outcome.status == crate::vc::trust::issuer::IssuerTrustStatus::Trusted =>
        {
            Some(AnchorPolicy::Require)
        }
        IssuerTrustMode::Report => Some(AnchorPolicy::IntegrityOnly),
    }
}

/// A path from an issuer chain to an anchor that is revoked or out of its validity period.
#[cfg(not(target_arch = "wasm32"))]
fn rejected_issuer_chain(
    error: one_core::proto::certificate_validator::Error,
) -> crate::vc::formats::Error {
    crate::vc::formats::VerifyingSnafu {
        details: format!("Issuer certificate chain is not valid: {error}"),
    }
    .build()
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
                    response_uri: None,
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims.claims).await;
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

        case.assert_verified_claims(&claims.claims).await;
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
                    response_uri: None,
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims.claims).await;
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
                    response_uri: None,
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims.claims).await;
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
                    response_uri: None,
                }),
                &vp,
                &ReqwestClientBuilder::new().insecure().build().unwrap(),
            )
            .await
            .unwrap();

        case.assert_verified_claims(&claims.claims).await;
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
                    response_uri: None,
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

    #[cfg(not(target_arch = "wasm32"))]
    mod mdoc_status {
        use crate::did::universal::UniversalResolver;
        use crate::http::{HttpResponse, HttpSnafu, MockHttpClient};
        use crate::utils::http::test::{mock_http_fn, mock_http_fn_with_plain_text_resp};
        use crate::utils::test_utils::{anchors, mdl_iaca};
        use crate::vc::core::{VerificationParams, Verifier, VerifierService};
        use crate::vc::formats::mso_mdoc;
        use crate::vc::formats::mso_mdoc::tests::{sample_binder, sample_mso_mdoc_vp_with_status};
        use crate::vc::status_formats::status_list_token_jwt;
        use crate::vc::status_formats::status_list_token_jwt::tests::{
            status_list_root_ca, status_list_signer_cert, x5c_status_list_token,
        };
        use crate::vc::trust::issuer::{
            IssuerTrustConfig, IssuerTrustMode, IssuerTrustStatus, IssuerTrustVerification,
            TrustAnchor,
        };
        use crate::vc::{Presentation, VCStatus};
        use oauth2::http::Method;
        use oauth2::http::header::CONTENT_TYPE;
        use rstest::rstest;
        use serde_json::{Value, json};
        use std::str::FromStr;
        use url::Url;

        const STATUS_LIST_URI: &str = "https://status.example/mdoc/1";
        const IDENTIFIER_LIST_URI: &str = "https://status.example/identifiers/1";
        const VALID: usize = 0;
        const INVALID: usize = 2;

        fn status_list(idx: usize) -> Value {
            json!({ "status_list": { "idx": idx, "uri": STATUS_LIST_URI } })
        }

        fn identifier_list() -> Value {
            json!({ "id": "6482", "uri": IDENTIFIER_LIST_URI })
        }

        /// Serves the fixture status list token once at [STATUS_LIST_URI].
        fn serving_status_list() -> MockHttpClient {
            let mut http_client = MockHttpClient::new();
            mock_http_fn_with_plain_text_resp(
                &mut http_client,
                Method::GET,
                Url::from_str(STATUS_LIST_URI).unwrap(),
                x5c_status_list_token(STATUS_LIST_URI, "statuslist+jwt", true),
                1.into(),
            );
            http_client
        }

        /// A verifier whose issuer anchor is `iaca` (an mDL issuer) and whose trusted
        /// certificates also hold the status list root unless `status_list_anchored` is false.
        fn verifier(
            iaca: &str,
            mode: IssuerTrustMode,
            status_list_anchored: bool,
        ) -> VerifierService {
            verifier_with(iaca, mode, status_list_anchored.then(status_list_root_ca))
        }

        fn verifier_with(
            iaca: &str,
            mode: IssuerTrustMode,
            status_list_anchor: Option<&str>,
        ) -> VerifierService {
            let mut trusted = vec![iaca];
            trusted.extend(status_list_anchor);
            VerifierService::new(mso_mdoc::tests::VERIFIER, UniversalResolver::default())
                .with_verification_params(VerificationParams {
                    trusted_certs: Some(anchors(&trusted)),
                    issuer_trust: Some(IssuerTrustConfig {
                        mode,
                        anchors: vec![TrustAnchor {
                            pem: iaca.to_string(),
                            source_ref: None,
                            role: Some("eaa_provider".to_string()),
                            service_type: None,
                        }],
                        ..Default::default()
                    }),
                })
        }

        async fn verify(
            status: Value,
            mode: IssuerTrustMode,
            status_list_anchored: bool,
            http_client: MockHttpClient,
        ) -> crate::vc::core::Result<IssuerTrustVerification> {
            let (vp, iaca) = sample_mso_mdoc_vp_with_status(status);
            verifier(&iaca, mode, status_list_anchored)
                .verify_presentation(
                    Some(sample_binder()),
                    &Presentation::MsoMdoc(mso_mdoc::Presentation {
                        value: vp,
                        enc_pub_key: None,
                    }),
                    &http_client,
                )
                .await
        }

        fn assert_fails_with<T: std::fmt::Debug>(
            result: crate::vc::core::Result<T>,
            expected: &str,
        ) {
            let error = result.unwrap_err().to_string();
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        #[tokio::test]
        async fn valid_mdoc_status_is_trusted_under_enforce() {
            let verified = verify(
                status_list(VALID),
                IssuerTrustMode::Enforce,
                true,
                serving_status_list(),
            )
            .await
            .unwrap();

            assert_eq!(verified.outcome.status, IssuerTrustStatus::Trusted);
        }

        #[rstest]
        #[case::enforce(IssuerTrustMode::Enforce)]
        #[case::report(IssuerTrustMode::Report)]
        #[tokio::test]
        async fn revoked_mdoc_is_rejected(#[case] mode: IssuerTrustMode) {
            let result = verify(status_list(INVALID), mode, true, serving_status_list()).await;

            assert_fails_with(
                result,
                "The status of the verifiable credential is 'Invalid'",
            );
        }

        #[tokio::test]
        async fn status_list_signer_under_no_anchor_fails_under_enforce() {
            let result = verify(
                status_list(VALID),
                IssuerTrustMode::Enforce,
                false,
                serving_status_list(),
            )
            .await;

            assert_fails_with(result, "Certificate chain is not trusted");
        }

        #[tokio::test]
        async fn status_list_signer_held_as_a_revocation_anchor_passes_under_enforce() {
            let (vp, iaca) = sample_mso_mdoc_vp_with_status(status_list(VALID));

            let verified = verifier_with(
                &iaca,
                IssuerTrustMode::Enforce,
                Some(status_list_signer_cert()),
            )
            .verify_presentation(
                Some(sample_binder()),
                &Presentation::MsoMdoc(mso_mdoc::Presentation {
                    value: vp,
                    enc_pub_key: None,
                }),
                &serving_status_list(),
            )
            .await
            .unwrap();

            assert_eq!(verified.outcome.status, IssuerTrustStatus::Trusted);
        }

        #[tokio::test]
        async fn status_list_signer_under_no_anchor_fails_for_a_trusted_issuer_under_report() {
            let result = verify(
                status_list(VALID),
                IssuerTrustMode::Report,
                false,
                serving_status_list(),
            )
            .await;

            assert_fails_with(result, "Certificate chain is not trusted");
        }

        #[tokio::test]
        async fn status_list_signer_under_no_anchor_passes_for_an_untrusted_issuer_under_report() {
            let (vp, _) = sample_mso_mdoc_vp_with_status(status_list(VALID));
            let unrelated_iaca = mdl_iaca(&test_fixtures::JWK::generate_p256());

            let verified = verifier(&unrelated_iaca, IssuerTrustMode::Report, false)
                .verify_presentation(
                    Some(sample_binder()),
                    &Presentation::MsoMdoc(mso_mdoc::Presentation {
                        value: vp,
                        enc_pub_key: None,
                    }),
                    &serving_status_list(),
                )
                .await
                .unwrap();

            assert_eq!(verified.outcome.status, IssuerTrustStatus::Untrusted);
        }

        #[rstest]
        #[case::enforce(IssuerTrustMode::Enforce)]
        #[case::report(IssuerTrustMode::Report)]
        #[tokio::test]
        async fn unreachable_status_list_is_rejected(#[case] mode: IssuerTrustMode) {
            let mut http_client = MockHttpClient::new();
            mock_http_fn(
                &mut http_client,
                Method::GET,
                Url::from_str(STATUS_LIST_URI).unwrap(),
                |_| {
                    HttpSnafu {
                        details: "connection refused",
                    }
                    .fail()
                },
                1.into(),
            );

            let result = verify(status_list(VALID), mode, true, http_client).await;

            assert_fails_with(result, "Could not fetch status list");
        }

        #[tokio::test]
        async fn status_list_served_only_as_cwt_is_not_supported() {
            let mut http_client = MockHttpClient::new();
            mock_http_fn(
                &mut http_client,
                Method::GET,
                Url::from_str(STATUS_LIST_URI).unwrap(),
                |_| {
                    let mut response = HttpResponse::new(vec![0xd2, 0x84]);
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, "application/statuslist+cwt".parse().unwrap());
                    Ok(response)
                },
                1.into(),
            );

            let result = verify(
                status_list(VALID),
                IssuerTrustMode::Enforce,
                true,
                http_client,
            )
            .await;

            assert_fails_with(
                result,
                "status list format not supported: application/statuslist+cwt",
            );
        }

        #[tokio::test]
        async fn identifier_list_beside_a_status_list_is_not_fetched() {
            let mut status = status_list(VALID);
            status["identifier_list"] = identifier_list();

            // the mock serves the status list only: a fetch of the identifier list would panic
            let verified = verify(
                status,
                IssuerTrustMode::Enforce,
                true,
                serving_status_list(),
            )
            .await
            .unwrap();

            assert_eq!(verified.outcome.status, IssuerTrustStatus::Trusted);
        }

        #[rstest]
        #[case::enforce(IssuerTrustMode::Enforce)]
        #[case::report(IssuerTrustMode::Report)]
        #[tokio::test]
        async fn identifier_list_only_is_rejected(#[case] mode: IssuerTrustMode) {
            let result = verify(
                json!({ "identifier_list": identifier_list() }),
                mode,
                true,
                MockHttpClient::new(),
            )
            .await;

            assert_fails_with(result, "status mechanism not supported: identifier_list");
        }

        #[tokio::test]
        async fn rejected_issuer_under_enforce_fetches_no_status() {
            let (vp, _) = sample_mso_mdoc_vp_with_status(status_list(INVALID));
            let unrelated_iaca = mdl_iaca(&test_fixtures::JWK::generate_p256());

            // no status list is served: a fetch would panic
            let error = verifier(&unrelated_iaca, IssuerTrustMode::Enforce, true)
                .verify_presentation(
                    Some(sample_binder()),
                    &Presentation::MsoMdoc(mso_mdoc::Presentation {
                        value: vp,
                        enc_pub_key: None,
                    }),
                    &MockHttpClient::new(),
                )
                .await
                .unwrap_err();

            let crate::vc::core::Error::IssuerNotTrusted { verified } = error else {
                panic!("expected IssuerNotTrusted, got {error}");
            };
            assert_eq!(verified.outcome.status, IssuerTrustStatus::Untrusted);
        }

        #[tokio::test]
        async fn index_beyond_the_status_list_is_rejected() {
            let result = verify(
                status_list(100_000),
                IssuerTrustMode::Enforce,
                true,
                serving_status_list(),
            )
            .await;

            assert_fails_with(result, "failed to get index 100000");
        }

        #[rstest]
        #[case::empty(json!({}))]
        #[case::null_status_list(json!({ "status_list": null }))]
        #[tokio::test]
        async fn status_naming_no_mechanism_is_rejected(#[case] status: Value) {
            let result = verify(status, IssuerTrustMode::Report, true, MockHttpClient::new()).await;

            let error = format!("{:?}", result.unwrap_err());
            assert!(error.contains("MSO status"), "unexpected error: {error}");
        }

        #[tokio::test]
        async fn obtain_credential_status_rejects_identifier_list_only() {
            let (vp, iaca) =
                sample_mso_mdoc_vp_with_status(json!({ "identifier_list": identifier_list() }));

            let result = verifier(&iaca, IssuerTrustMode::Enforce, true)
                .obtain_credential_status(
                    &Presentation::MsoMdoc(mso_mdoc::Presentation {
                        value: vp,
                        enc_pub_key: None,
                    }),
                    &MockHttpClient::new(),
                )
                .await;

            assert_fails_with(result, "status mechanism not supported: identifier_list");
        }

        #[tokio::test]
        async fn mdoc_without_status_verifies_without_a_fetch() {
            let (vp, iaca) = mso_mdoc::tests::sample_mso_mdoc_vp_with_iaca();

            let verified = verifier(&iaca, IssuerTrustMode::Enforce, true)
                .verify_presentation(
                    Some(sample_binder()),
                    &Presentation::MsoMdoc(mso_mdoc::Presentation {
                        value: vp,
                        enc_pub_key: None,
                    }),
                    &MockHttpClient::new(),
                )
                .await
                .unwrap();

            assert_eq!(verified.outcome.status, IssuerTrustStatus::Trusted);
        }

        #[tokio::test]
        async fn verify_presentation_rejects_a_revoked_mdoc() {
            let (vp, iaca) = sample_mso_mdoc_vp_with_status(status_list(INVALID));

            let result = verifier(&iaca, IssuerTrustMode::Enforce, true)
                .verify_presentation(
                    Some(sample_binder()),
                    &Presentation::MsoMdoc(mso_mdoc::Presentation {
                        value: vp,
                        enc_pub_key: None,
                    }),
                    &serving_status_list(),
                )
                .await;

            assert_fails_with(
                result,
                "The status of the verifiable credential is 'Invalid'",
            );
        }

        #[tokio::test]
        async fn obtain_credential_status_reads_the_mdoc_status() {
            let (vp, iaca) = sample_mso_mdoc_vp_with_status(status_list(INVALID));

            let status = verifier(&iaca, IssuerTrustMode::Enforce, true)
                .obtain_credential_status(
                    &Presentation::MsoMdoc(mso_mdoc::Presentation {
                        value: vp,
                        enc_pub_key: None,
                    }),
                    &serving_status_list(),
                )
                .await
                .unwrap();

            assert_eq!(
                status,
                Some(VCStatus::StatusListToken(
                    status_list_token_jwt::VCStatus::Invalid
                ))
            );
        }
    }
}
