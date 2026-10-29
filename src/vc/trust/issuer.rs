use serde::{Deserialize, Serialize};

/// What an untrusted issuer does to a verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerTrustMode {
    #[default]
    Enforce,
    Report,
}

/// A certificate trusted to anchor credential issuers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    /// PEM of the anchor certificate: a root, an intermediate CA or a listed signing certificate.
    pub pem: String,
    /// Opaque reference echoed in the trust result (e.g. the trust list it came from).
    pub source_ref: Option<String>,
    /// Role the anchor is trusted for (e.g. `pid_provider`), echoed in the trust result.
    pub role: Option<String>,
    /// Type of the trust-list service that granted the anchor (e.g.
    /// `http://uri.etsi.org/19602/SvcType/PID/Issuance`).
    pub service_type: Option<String>,
}

impl TrustAnchor {
    pub fn new(pem: impl Into<String>) -> Self {
        Self {
            pem: pem.into(),
            source_ref: None,
            role: None,
            service_type: None,
        }
    }

    /// Whether the anchor may anchor a credential issuer.
    pub fn anchors_issuers(&self) -> bool {
        match self.service_type.as_deref() {
            None => true,
            Some(service_type) => {
                service_type
                    .strip_prefix(LOTE_SERVICE_TYPE_PREFIX)
                    .is_some_and(|kind| kind.ends_with("/Issuance"))
                    || ISSUING_TSL_SERVICE_TYPES.contains(&service_type)
            }
        }
    }

    /// Whether the anchor may anchor an issuer of `category`.
    pub fn anchors_category(
        &self,
        category: CredentialCategory,
        roleless: RolelessAnchors,
    ) -> bool {
        match self.role.as_deref() {
            Some(role) => role == category.anchor_role(),
            None => {
                roleless == RolelessAnchors::AllCategories || category == CredentialCategory::Eaa
            }
        }
    }
}

/// Prefix of TS 119 602 service types (`…/<kind>/Issuance`, `…/<kind>/Revocation`).
const LOTE_SERVICE_TYPE_PREFIX: &str = "http://uri.etsi.org/19602/SvcType/";

/// TS 119 612 service types that issue attestations, plus the EUDI pilot PID provider type.
pub const ISSUING_TSL_SERVICE_TYPES: [&str; 4] = [
    "http://uri.etsi.org/TrstSvc/Svctype/EAA",
    "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
    "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA",
    "http://uri.etsi.org/Svc/Svctype/Provider/PID",
];

/// EUDI attestation category; decides which anchors may anchor the issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialCategory {
    /// Person Identification Data: anchored by PID providers.
    Pid,
    /// Qualified electronic attestation of attributes: anchored by QEAA providers.
    Qeaa,
    /// Public-sector electronic attestation of attributes: anchored by PuB-EAA providers.
    PubEaa,
    /// Any other attestation: anchored by EAA providers.
    Eaa,
}

impl CredentialCategory {
    /// PID, QEAA and PuB-EAA providers are identified by X.509 certificates, so an issuer without
    /// a chain is refused.
    pub fn is_regulated(self) -> bool {
        self != Self::Eaa
    }

    /// Trust-list role that anchors this category.
    pub fn anchor_role(self) -> &'static str {
        match self {
            Self::Pid => "pid_provider",
            Self::Qeaa => "qeaa_provider",
            Self::PubEaa => "pub_eaa_provider",
            Self::Eaa => "eaa_provider",
        }
    }
}

/// The `category` claim value of a qualified EAA (ETSI TS 119 472-1).
pub const QUALIFIED_EAA_CATEGORY: &str = "urn:etsi:esi:eaa:eu:qualified";

/// The `category` claim value of a public-sector EAA (ETSI TS 119 472-1).
pub const PUB_EAA_CATEGORY: &str = "urn:etsi:esi:eaa:eu:pub";

/// EUDI PID types (SD-JWT VC `vct`, mdoc docType), always classified as [CredentialCategory::Pid].
pub const EUDI_PID_TYPES: [&str; 3] = [
    "urn:eudi:pid:*",
    "urn:eu.europa.ec.eudi:pid:*",
    "eu.europa.ec.eudi.pid.1",
];

/// Credential types (`vct`, docType) classified as PID, QEAA or PuB-EAA, in addition to
/// [EUDI_PID_TYPES]. A trailing `*` matches by prefix. Unlisted credentials fall back to their
/// `category` claim, then to [CredentialCategory::Eaa]; request that claim when relying on it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CredentialClassification {
    pub pid: Vec<String>,
    pub qeaa: Vec<String>,
    pub pub_eaa: Vec<String>,
}

impl CredentialClassification {
    /// Category from the credential type and its `category` claim; a listed type wins.
    pub fn classify(
        &self,
        credential_type: Option<&str>,
        declared_category: Option<&str>,
    ) -> CredentialCategory {
        let matches = |listed: &str| {
            credential_type.is_some_and(|credential_type| match listed.strip_suffix('*') {
                Some(prefix) => credential_type.starts_with(prefix),
                None => listed == credential_type,
            })
        };
        let listed = |types: &[String]| types.iter().any(|listed| matches(listed));
        if EUDI_PID_TYPES.iter().any(|listed| matches(listed)) || listed(&self.pid) {
            return CredentialCategory::Pid;
        }
        if listed(&self.qeaa) {
            return CredentialCategory::Qeaa;
        }
        if listed(&self.pub_eaa) {
            return CredentialCategory::PubEaa;
        }
        match declared_category {
            Some(QUALIFIED_EAA_CATEGORY) => CredentialCategory::Qeaa,
            Some(PUB_EAA_CATEGORY) => CredentialCategory::PubEaa,
            _ => CredentialCategory::Eaa,
        }
    }

    /// Category of verified claims: `vct` and `category` at the top level (SD-JWT VC), or
    /// `doctype` with `category` in any namespace (mdoc).
    pub fn classify_claims(&self, claims: &crate::vc::claims::Claims) -> CredentialCategory {
        if let Some(vct) = claims.get("vct").and_then(|claim| claim.as_str()) {
            let category = claims.get("category").and_then(|claim| claim.as_str());
            return self.classify(Some(vct), category);
        }
        let doctype = claims.get("doctype").and_then(|claim| claim.as_str());
        // a qualified mark wins over a public one
        let declares = |category: &str| {
            claims.claims().values().any(|namespace| {
                namespace.get("category").and_then(|claim| claim.as_str()) == Some(category)
            })
        };
        let category = [QUALIFIED_EAA_CATEGORY, PUB_EAA_CATEGORY]
            .into_iter()
            .find(|category| declares(category));
        self.classify(doctype, category)
    }
}

/// Which categories an anchor without a role (e.g. a trusted root) may anchor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolelessAnchors {
    /// Every category.
    #[default]
    AllCategories,
    /// Only [CredentialCategory::Eaa]; other categories need an anchor with a matching role.
    EaaOnly,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuerTrustConfig {
    pub mode: IssuerTrustMode,
    /// Tried in order; the first anchor that validates a chain is reported.
    pub anchors: Vec<TrustAnchor>,
    /// How credentials are classified into categories.
    pub classification: CredentialClassification,
    /// Which categories anchors without a role may anchor.
    pub roleless_anchors: RolelessAnchors,
}

impl IssuerTrustConfig {
    /// The anchors that may anchor an issuer of `category`, in order.
    pub fn anchors_for(&self, category: CredentialCategory) -> Vec<TrustAnchor> {
        self.anchors
            .iter()
            .filter(|anchor| anchor.anchors_category(category, self.roleless_anchors))
            .cloned()
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerTrustStatus {
    Trusted,
    Untrusted,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerTrustReason {
    /// The chain is valid but reaches none of the anchors.
    NoAnchorMatch,
    /// The chain cannot be validated.
    ChainInvalid,
    /// No anchor was supplied.
    NoAnchorsConfigured,
    /// Anchors were supplied, but none for the credential's category.
    NoAnchorsForCategory,
    /// The issuer key was resolved from a DID, not a certificate chain (not evaluated).
    DidIssuer,
    /// A DID-identified issuer of a PID, QEAA or PuB-EAA, which requires X.509.
    DidIssuerNotAllowed,
}

/// A presentation verified by [crate::vc::core::Verifier::verify_presentation_with_issuer_trust].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IssuerTrustVerification {
    pub claims: crate::vc::claims::Claims,
    pub outcome: IssuerTrustOutcome,
    /// AKIs of the issuer chain, for DCQL `aki` trusted authorities.
    pub issuer_chain_akis: Option<Vec<Vec<u8>>>,
}

impl IssuerTrustVerification {
    pub fn new(
        claims: crate::vc::claims::Claims,
        outcome: IssuerTrustOutcome,
        issuer_chain_akis: Option<Vec<Vec<u8>>>,
    ) -> Self {
        Self {
            claims,
            outcome,
            issuer_chain_akis,
        }
    }

    /// A presentation whose issuer has no certificate chain.
    pub fn without_chain(claims: crate::vc::claims::Claims, outcome: IssuerTrustOutcome) -> Self {
        Self::new(claims, outcome, None)
    }
}

/// Issuer trust of one credential (camelCase, as the wrappers return it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerTrustOutcome {
    pub status: IssuerTrustStatus,
    /// Subject Key Identifier of the matched anchor, when trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_ski: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<IssuerTrustReason>,
    /// Category the credential was evaluated under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<CredentialCategory>,
}

impl IssuerTrustOutcome {
    pub fn trusted(anchor: &TrustAnchor, anchor_ski: Option<String>) -> Self {
        Self {
            status: IssuerTrustStatus::Trusted,
            anchor_ski,
            source_ref: anchor.source_ref.clone(),
            role: anchor.role.clone(),
            reason: None,
            category: None,
        }
    }

    /// The outcome for an issuer without a certificate chain.
    pub fn without_chain(category: CredentialCategory) -> Self {
        let outcome = if category.is_regulated() {
            Self::untrusted(IssuerTrustReason::DidIssuerNotAllowed)
        } else {
            Self::not_evaluated(IssuerTrustReason::DidIssuer)
        };
        outcome.with_category(category)
    }

    /// This outcome, for a credential of `category`.
    pub fn with_category(mut self, category: CredentialCategory) -> Self {
        self.category = Some(category);
        self
    }

    pub fn untrusted(reason: IssuerTrustReason) -> Self {
        Self::without_anchor(IssuerTrustStatus::Untrusted, reason)
    }

    pub fn not_evaluated(reason: IssuerTrustReason) -> Self {
        Self::without_anchor(IssuerTrustStatus::NotEvaluated, reason)
    }

    fn without_anchor(status: IssuerTrustStatus, reason: IssuerTrustReason) -> Self {
        Self {
            status,
            anchor_ski: None,
            source_ref: None,
            role: None,
            reason: Some(reason),
            category: None,
        }
    }

    /// Whether this outcome fails a verification in [IssuerTrustMode::Enforce].
    pub fn rejected_when_enforced(&self) -> bool {
        match self.status {
            IssuerTrustStatus::Trusted => false,
            IssuerTrustStatus::Untrusted => true,
            IssuerTrustStatus::NotEvaluated => self.reason != Some(IssuerTrustReason::DidIssuer),
        }
    }
}

/// Issuer trust of one presented credential, by DCQL credential query id and index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerTrust {
    pub credential_id: String,
    pub index: usize,
    #[serde(flatten)]
    pub outcome: IssuerTrustOutcome,
}

/// Where the issuer key of an SD-JWT VC presentation comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SdJwtIssuerKey {
    /// An `x5c` chain (PEM, leaf first), used for a URL issuer.
    X5c(String),
    /// A DID or anything else that is not a certificate chain.
    Other,
}

/// The issuer key source of a compact SD-JWT VC presentation (`issuer-jwt~disclosures~kb-jwt`).
/// Fails when the issuer JWT or its `x5c` cannot be read, rather than falling back to `Other`.
#[cfg(not(target_arch = "wasm32"))]
pub fn sd_jwt_issuer_key(presentation: &str) -> Result<SdJwtIssuerKey, crate::vc::formats::Error> {
    let invalid = |details: String| crate::vc::formats::VerifyingSnafu { details }.build();
    let issuer_jwt = presentation.split('~').next().unwrap_or_default();
    let (header, payload) = ssi::claims::jws::decode_unverified(issuer_jwt)
        .map_err(|e| invalid(format!("Issuer JWT cannot be decoded: {e}")))?;
    let claims = serde_json::from_slice::<serde_json::Value>(&payload)
        .map_err(|e| invalid(format!("Issuer JWT payload is not JSON: {e}")))?;
    let iss_is_did = claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|iss| iss.starts_with("did:"));
    match header.x509_certificate_chain {
        Some(x5c) if !iss_is_did => one_core::mapper::x509::x5c_into_pem_chain(&x5c)
            .map(SdJwtIssuerKey::X5c)
            .map_err(|e| invalid(format!("Issuer x5c is not a certificate chain: {e}"))),
        _ => Ok(SdJwtIssuerKey::Other),
    }
}

/// Evaluates an issuer chain (PEM, leaf first) against the issuer `anchors`, in order. An anchor
/// matches when the chain contains it or validates up to it. Only anchors the chain names as an
/// issuer are tried: by AKI, or by subject name when the chain has no AKIs.
///
/// Certificates below the matched anchor are checked for revocation. A revoked or expired path to
/// an anchor is an error, not an outcome, so it fails even in `report` mode; it is returned only
/// when no other anchor matches.
#[cfg(not(target_arch = "wasm32"))]
pub async fn evaluate_chain(
    certificate_validator: &dyn one_core::proto::certificate_validator::CertificateValidator,
    chain_pem: &str,
    anchors: &[TrustAnchor],
) -> Result<IssuerTrustOutcome, one_core::proto::certificate_validator::Error> {
    use one_core::mapper::x509::{
        der_chain_into_pem_chain, get_akis_for_pem_chain, pem_to_subject_key_identifier,
        subject_key_identifier,
    };
    use one_core::proto::certificate_validator::{
        CertSelection, CertificateValidationOptions, EnforceKeyUsage,
    };

    if anchors.is_empty() {
        return Ok(IssuerTrustOutcome::not_evaluated(
            IssuerTrustReason::NoAnchorsConfigured,
        ));
    }

    let below_anchor = || {
        CertificateValidationOptions::signature_and_revocation_below_anchor(Some(vec![
            EnforceKeyUsage::DigitalSignature,
        ]))
    };
    let chain_ders: Vec<Vec<u8>> = x509_parser::pem::Pem::iter_from_buffer(chain_pem.as_bytes())
        .filter_map(Result::ok)
        .map(|pem| pem.contents)
        .collect();
    let chain_akis = get_akis_for_pem_chain(chain_pem.as_bytes()).unwrap_or_default();
    let chain_issuers: Vec<Vec<u8>> = chain_ders
        .iter()
        .filter_map(|der| x509_parser::parse_x509_certificate(der).ok())
        .map(|(_, certificate)| certificate.issuer().as_raw().to_vec())
        .collect();
    let mut rejected_path = None;

    for anchor in anchors.iter().filter(|anchor| anchor.anchors_issuers()) {
        let Ok((_, anchor_pem)) = x509_parser::pem::parse_x509_pem(anchor.pem.as_bytes()) else {
            tracing::warn!("skipping an unparseable trust anchor");
            continue;
        };
        let anchor_certificate = anchor_pem.parse_x509().ok();
        let anchor_ski = anchor_certificate
            .as_ref()
            .and_then(|certificate| subject_key_identifier(certificate).ok().flatten());

        let validated = match chain_ders
            .iter()
            .position(|der| *der == anchor_pem.contents)
        {
            // the leaf itself is listed (e.g. a listed signing certificate)
            Some(0) => return Ok(IssuerTrustOutcome::trusted(anchor, anchor_ski)),
            // the anchor is in the chain: the certificates under it are checked for revocation
            Some(position) => {
                let path = der_chain_into_pem_chain(chain_ders[..=position].to_vec());
                certificate_validator
                    .parse_pem_chain(&path, below_anchor())
                    .await
            }
            None => {
                let named_by_chain = if chain_akis.is_empty() {
                    anchor_certificate.as_ref().is_some_and(|certificate| {
                        let subject = certificate.subject().as_raw();
                        chain_issuers
                            .iter()
                            .any(|issuer| issuer.as_slice() == subject)
                    })
                } else {
                    !matches!(
                        pem_to_subject_key_identifier(&anchor.pem),
                        Ok(Some(ski)) if !chain_akis.contains(&ski)
                    )
                };
                if !named_by_chain {
                    continue;
                }
                certificate_validator
                    .validate_chain_against_ca_chain(
                        chain_pem,
                        &anchor.pem,
                        below_anchor(),
                        CertSelection::Leaf,
                    )
                    .await
            }
        };
        match validated {
            Ok(_) => return Ok(IssuerTrustOutcome::trusted(anchor, anchor_ski)),
            Err(error) if crate::utils::x509_truststore::is_rejected_path(&error) => {
                tracing::debug!(%error, "issuer chain reaches an anchor but is not valid");
                rejected_path.get_or_insert(error);
            }
            Err(error) => tracing::debug!(%error, "issuer chain does not validate to an anchor"),
        }
    }

    if let Some(error) = rejected_path {
        return Err(error);
    }
    Ok(
        match crate::utils::x509_truststore::verify_chain_integrity(
            certificate_validator,
            chain_pem,
        )
        .await
        {
            Ok(_) => IssuerTrustOutcome::untrusted(IssuerTrustReason::NoAnchorMatch),
            Err(_) => IssuerTrustOutcome::untrusted(IssuerTrustReason::ChainInvalid),
        },
    )
}

/// [evaluate_chain] against the anchors for `category`; `no_anchors_for_category` when anchors
/// exist but none fit.
#[cfg(not(target_arch = "wasm32"))]
pub async fn evaluate_chain_for_category(
    certificate_validator: &dyn one_core::proto::certificate_validator::CertificateValidator,
    chain_pem: &str,
    config: &IssuerTrustConfig,
    category: CredentialCategory,
) -> Result<IssuerTrustOutcome, one_core::proto::certificate_validator::Error> {
    let anchors = config.anchors_for(category);
    let issuing = |anchors: &[TrustAnchor]| anchors.iter().any(TrustAnchor::anchors_issuers);
    let outcome = if !issuing(&anchors) && issuing(&config.anchors) {
        IssuerTrustOutcome::untrusted(IssuerTrustReason::NoAnchorsForCategory)
    } else {
        evaluate_chain(certificate_validator, chain_pem, &anchors).await?
    };
    Ok(outcome.with_category(category))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use one_core::proto::certificate_validator::CertificateValidatorImpl;

    use super::*;
    use crate::utils::x509_truststore::tests::{
        CrlPki, github_root_ca, test_issuer_cert, test_root_ca,
    };

    #[test]
    fn issuer_trust_serializes_in_camel_case_without_absent_fields() {
        let trusted = IssuerTrust {
            credential_id: "pid".to_string(),
            index: 1,
            outcome: IssuerTrustOutcome {
                status: IssuerTrustStatus::Trusted,
                anchor_ski: Some("ab:cd".to_string()),
                source_ref: Some("https://lote.example.com".to_string()),
                role: Some("pid_provider".to_string()),
                reason: None,
                category: Some(CredentialCategory::Pid),
            },
        };
        let untrusted = IssuerTrust {
            credential_id: "mDL".to_string(),
            index: 0,
            outcome: IssuerTrustOutcome::untrusted(IssuerTrustReason::NoAnchorMatch),
        };

        assert_eq!(
            serde_json::to_value([trusted, untrusted]).unwrap(),
            serde_json::json!([
                {
                    "credentialId": "pid", "index": 1, "status": "trusted", "anchorSki": "ab:cd",
                    "sourceRef": "https://lote.example.com", "role": "pid_provider",
                    "category": "pid"
                },
                {
                    "credentialId": "mDL", "index": 0, "status": "untrusted",
                    "reason": "no_anchor_match"
                }
            ])
        );
    }

    #[rstest::rstest]
    #[case::sd_jwt_pid(Some("urn:eudi:pid:1"), None, CredentialCategory::Pid)]
    #[case::national_sd_jwt_pid(Some("urn:eudi:pid:de:1"), None, CredentialCategory::Pid)]
    #[case::reference_sd_jwt_pid(
        Some("urn:eu.europa.ec.eudi:pid:1"),
        None,
        CredentialCategory::Pid
    )]
    #[case::mdoc_pid(Some("eu.europa.ec.eudi.pid.1"), None, CredentialCategory::Pid)]
    #[case::qualified_by_category(
        Some("https://example.com/diploma"),
        Some(QUALIFIED_EAA_CATEGORY),
        CredentialCategory::Qeaa
    )]
    #[case::public_by_category(
        Some("https://example.gov/permit"),
        Some(PUB_EAA_CATEGORY),
        CredentialCategory::PubEaa
    )]
    #[case::a_pid_type_wins_over_its_category(
        Some("urn:eudi:pid:1"),
        Some(QUALIFIED_EAA_CATEGORY),
        CredentialCategory::Pid
    )]
    #[case::unknown_category(
        Some("https://example.com/diploma"),
        Some("urn:example:other"),
        CredentialCategory::Eaa
    )]
    #[case::mdl(Some("org.iso.18013.5.1.mDL"), None, CredentialCategory::Eaa)]
    #[case::untyped(None, None, CredentialCategory::Eaa)]
    #[case::pid_prefix_is_not_a_substring(Some("x-urn:eudi:pid:1"), None, CredentialCategory::Eaa)]
    fn classifies_credentials_by_type_and_category(
        #[case] credential_type: Option<&str>,
        #[case] declared_category: Option<&str>,
        #[case] expected: CredentialCategory,
    ) {
        assert_eq!(
            CredentialClassification::default().classify(credential_type, declared_category),
            expected
        );
    }

    #[test]
    fn configured_types_add_to_the_eudi_pid_types() {
        let classification = CredentialClassification {
            pid: vec!["urn:example:pid:*".to_string()],
            qeaa: vec!["https://example.com/qualified/*".to_string()],
            pub_eaa: vec!["eu.example.pub.1".to_string()],
        };

        assert_eq!(
            classification.classify(Some("urn:example:pid:1"), None),
            CredentialCategory::Pid
        );
        assert_eq!(
            classification.classify(Some("urn:eudi:pid:1"), None),
            CredentialCategory::Pid
        );
        assert_eq!(
            classification.classify(Some("https://example.com/qualified/diploma"), None),
            CredentialCategory::Qeaa
        );
        assert_eq!(
            classification.classify(Some("eu.example.pub.1"), None),
            CredentialCategory::PubEaa
        );
        // a listed type wins over a contradicting category claim
        assert_eq!(
            classification.classify(Some("eu.example.pub.1"), Some(QUALIFIED_EAA_CATEGORY)),
            CredentialCategory::PubEaa
        );
    }

    #[test]
    fn classifies_claims_from_vct_or_doctype_and_a_category_claim() {
        let classification = CredentialClassification::default();
        let claims = |value: serde_json::Value| -> crate::vc::claims::Claims {
            serde_json::from_value(value).unwrap()
        };

        let sd_jwt = claims(serde_json::json!({ "vct": "urn:eudi:pid:1" }));
        let qualified_sd_jwt = claims(serde_json::json!({
            "vct": "https://example.com/diploma", "category": QUALIFIED_EAA_CATEGORY
        }));
        // an SD-JWT VC's `category` counts only at the top level
        let nested = claims(serde_json::json!({
            "vct": "https://example.com/diploma",
            "address": { "category": QUALIFIED_EAA_CATEGORY }
        }));
        // any mdoc namespace may mark the credential qualified
        let mdoc = claims(serde_json::json!({
            "doctype": "eu.example.diploma.1",
            "eu.example.a": { "category": "other" },
            "eu.example.b": { "category": QUALIFIED_EAA_CATEGORY }
        }));
        let public_sd_jwt = claims(serde_json::json!({
            "vct": "https://example.gov/permit", "category": PUB_EAA_CATEGORY
        }));
        // a qualified mark in one namespace wins over a public mark in another
        let mixed_mdoc = claims(serde_json::json!({
            "doctype": "eu.example.permit.1",
            "eu.example.a": { "category": PUB_EAA_CATEGORY },
            "eu.example.b": { "category": QUALIFIED_EAA_CATEGORY }
        }));
        let public_mdoc = claims(serde_json::json!({
            "doctype": "eu.example.permit.1",
            "eu.example.a": { "category": PUB_EAA_CATEGORY }
        }));

        assert_eq!(
            classification.classify_claims(&sd_jwt),
            CredentialCategory::Pid
        );
        assert_eq!(
            classification.classify_claims(&qualified_sd_jwt),
            CredentialCategory::Qeaa
        );
        assert_eq!(
            classification.classify_claims(&nested),
            CredentialCategory::Eaa
        );
        assert_eq!(
            classification.classify_claims(&mdoc),
            CredentialCategory::Qeaa
        );
        assert_eq!(
            classification.classify_claims(&public_sd_jwt),
            CredentialCategory::PubEaa
        );
        assert_eq!(
            classification.classify_claims(&mixed_mdoc),
            CredentialCategory::Qeaa
        );
        assert_eq!(
            classification.classify_claims(&public_mdoc),
            CredentialCategory::PubEaa
        );
    }

    #[test]
    fn an_issuer_without_a_chain_is_refused_only_for_regulated_categories() {
        for category in [
            CredentialCategory::Pid,
            CredentialCategory::Qeaa,
            CredentialCategory::PubEaa,
        ] {
            let outcome = IssuerTrustOutcome::without_chain(category);
            assert_eq!(outcome.reason, Some(IssuerTrustReason::DidIssuerNotAllowed));
            assert!(outcome.rejected_when_enforced());
        }
        let eaa = IssuerTrustOutcome::without_chain(CredentialCategory::Eaa);
        assert_eq!(eaa.reason, Some(IssuerTrustReason::DidIssuer));
        assert!(!eaa.rejected_when_enforced());
    }

    #[test]
    fn an_anchor_anchors_only_the_category_of_its_role() {
        let with_role = |role: &str| TrustAnchor {
            role: Some(role.to_string()),
            ..TrustAnchor::new("pem")
        };

        for (role, category) in [
            ("pid_provider", CredentialCategory::Pid),
            ("qeaa_provider", CredentialCategory::Qeaa),
            ("pub_eaa_provider", CredentialCategory::PubEaa),
            ("eaa_provider", CredentialCategory::Eaa),
        ] {
            assert!(with_role(role).anchors_category(category, RolelessAnchors::AllCategories));
        }
        assert!(
            !with_role("qeaa_provider")
                .anchors_category(CredentialCategory::Pid, RolelessAnchors::AllCategories)
        );
        assert!(
            !with_role("pid_provider")
                .anchors_category(CredentialCategory::Eaa, RolelessAnchors::AllCategories)
        );
        assert!(
            !with_role("wallet_provider")
                .anchors_category(CredentialCategory::Eaa, RolelessAnchors::AllCategories)
        );
    }

    #[test]
    fn a_roleless_anchor_anchors_regulated_categories_only_when_allowed() {
        let root = TrustAnchor::new("pem");

        assert!(root.anchors_category(CredentialCategory::Pid, RolelessAnchors::AllCategories));
        assert!(!root.anchors_category(CredentialCategory::Pid, RolelessAnchors::EaaOnly));
        assert!(!root.anchors_category(CredentialCategory::Qeaa, RolelessAnchors::EaaOnly));
        assert!(root.anchors_category(CredentialCategory::Eaa, RolelessAnchors::EaaOnly));
    }

    #[tokio::test]
    async fn anchors_of_another_category_leave_the_issuer_untrusted() {
        let chain = test_issuer_cert();
        let config = IssuerTrustConfig {
            anchors: vec![TrustAnchor {
                role: Some("qeaa_provider".to_string()),
                ..TrustAnchor::new(test_root_ca())
            }],
            ..Default::default()
        };

        let outcome = evaluate_chain_for_category(
            &CertificateValidatorImpl::default(),
            chain,
            &config,
            CredentialCategory::Pid,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            IssuerTrustOutcome {
                category: Some(CredentialCategory::Pid),
                ..IssuerTrustOutcome::untrusted(IssuerTrustReason::NoAnchorsForCategory)
            }
        );
        assert!(outcome.rejected_when_enforced());
    }

    #[tokio::test]
    async fn an_anchor_of_the_credential_category_trusts_its_issuer() {
        let chain = test_issuer_cert();
        let config = IssuerTrustConfig {
            anchors: vec![
                TrustAnchor {
                    role: Some("qeaa_provider".to_string()),
                    ..TrustAnchor::new(github_root_ca())
                },
                TrustAnchor {
                    role: Some("pid_provider".to_string()),
                    ..TrustAnchor::new(test_root_ca())
                },
            ],
            ..Default::default()
        };

        let outcome = evaluate_chain_for_category(
            &CertificateValidatorImpl::default(),
            chain,
            &config,
            CredentialCategory::Pid,
        )
        .await
        .unwrap();

        assert_eq!(outcome.status, IssuerTrustStatus::Trusted);
        assert_eq!(outcome.role.as_deref(), Some("pid_provider"));
        assert_eq!(outcome.category, Some(CredentialCategory::Pid));
    }

    fn anchor(pem: &str, source_ref: &str) -> TrustAnchor {
        TrustAnchor {
            pem: pem.to_string(),
            source_ref: Some(source_ref.to_string()),
            role: Some("pid_provider".to_string()),
            service_type: None,
        }
    }

    async fn evaluate(chain: &str, anchors: &[TrustAnchor]) -> IssuerTrustOutcome {
        evaluate_chain(&CertificateValidatorImpl::default(), chain, anchors)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn chain_reaching_an_anchor_is_trusted() {
        let outcome = evaluate(test_issuer_cert(), &[anchor(test_root_ca(), "list:1")]).await;
        assert_eq!(outcome.status, IssuerTrustStatus::Trusted);
        assert_eq!(outcome.source_ref.as_deref(), Some("list:1"));
        assert_eq!(outcome.role.as_deref(), Some("pid_provider"));
        assert!(outcome.anchor_ski.is_some());
        assert!(!outcome.rejected_when_enforced());
    }

    #[tokio::test]
    async fn valid_chain_reaching_no_anchor_is_untrusted() {
        let outcome = evaluate(test_issuer_cert(), &[anchor(github_root_ca(), "list:1")]).await;
        assert_eq!(outcome.status, IssuerTrustStatus::Untrusted);
        assert_eq!(outcome.reason, Some(IssuerTrustReason::NoAnchorMatch));
        assert!(outcome.rejected_when_enforced());
    }

    #[tokio::test]
    async fn no_anchors_is_not_evaluated_and_rejected_when_enforced() {
        let outcome = evaluate(test_issuer_cert(), &[]).await;
        assert_eq!(outcome.status, IssuerTrustStatus::NotEvaluated);
        assert_eq!(outcome.reason, Some(IssuerTrustReason::NoAnchorsConfigured));
        assert!(outcome.rejected_when_enforced());
    }

    #[tokio::test]
    async fn first_matching_anchor_is_reported() {
        let outcome = evaluate(
            test_issuer_cert(),
            &[
                anchor(github_root_ca(), "list:0"),
                anchor(test_root_ca(), "list:1"),
                anchor(test_root_ca(), "list:2"),
            ],
        )
        .await;
        assert_eq!(outcome.source_ref.as_deref(), Some("list:1"));
    }

    #[tokio::test]
    async fn a_listed_certificate_in_the_chain_is_an_anchor() {
        // a trust list may publish the issuer's own (non-CA) certificate
        let leaf = x509_parser::pem::Pem::iter_from_buffer(test_issuer_cert().as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let leaf_pem = one_core::mapper::x509::der_chain_into_pem_chain(vec![leaf.contents]);
        let outcome = evaluate(test_issuer_cert(), &[anchor(&leaf_pem, "list:1")]).await;
        assert_eq!(outcome.status, IssuerTrustStatus::Trusted);
    }

    fn with_service_type(anchor: TrustAnchor, service_type: &str) -> TrustAnchor {
        TrustAnchor {
            service_type: Some(service_type.to_string()),
            ..anchor
        }
    }

    #[test]
    fn only_issuing_service_anchors_anchor_issuers() {
        let root = anchor(test_root_ca(), "list:1");
        assert!(root.anchors_issuers());
        for issuing in [
            "http://uri.etsi.org/19602/SvcType/PID/Issuance",
            "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
            "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
            "http://uri.etsi.org/Svc/Svctype/Provider/PID",
        ] {
            assert!(
                with_service_type(root.clone(), issuing).anchors_issuers(),
                "{issuing}"
            );
        }
        for other in [
            "http://uri.etsi.org/19602/SvcType/PID/Revocation",
            "http://uri.etsi.org/19602/SvcType/PID/revocation",
            "http://uri.etsi.org/19602/SvcType/PID/Issuance/",
            "http://uri.etsi.org/19602/SvcType/Register",
            "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
            "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
            "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC",
            "http://example.com/Issuance",
            "",
        ] {
            assert!(
                !with_service_type(root.clone(), other).anchors_issuers(),
                "{other}"
            );
        }
    }

    #[tokio::test]
    async fn a_revocation_service_anchor_does_not_trust_an_issuer() {
        let revocation = with_service_type(
            anchor(test_root_ca(), "list:revocation"),
            "http://uri.etsi.org/19602/SvcType/PID/Revocation",
        );
        let issuance = with_service_type(
            anchor(test_root_ca(), "list:issuance"),
            "http://uri.etsi.org/19602/SvcType/PID/Issuance",
        );

        let untrusted = evaluate(test_issuer_cert(), std::slice::from_ref(&revocation)).await;
        let trusted = evaluate(test_issuer_cert(), &[revocation, issuance]).await;

        assert_eq!(untrusted.reason, Some(IssuerTrustReason::NoAnchorMatch));
        assert_eq!(trusted.source_ref.as_deref(), Some("list:issuance"));
    }

    #[tokio::test]
    async fn a_chain_without_authority_key_identifiers_is_tried_against_every_anchor() {
        let ca_key = test_fixtures::JWK::generate_p256();
        let ca = test_fixtures::x509(
            &serde_json::json!({
                "subject": [["CN", "AKI-less CA"]],
                "ca": true, "key_usages": ["key_cert_sign", "crl_sign"]
            }),
            &ca_key,
            None,
        );
        // a SAN, so rcgen writes an extensions block
        let leaf = test_fixtures::x509(
            &serde_json::json!({
                "subject": [["CN", "AKI-less Issuer"]], "sans": ["issuer.example"],
                "key_usages": ["digital_signature"]
            }),
            &test_fixtures::keys().issuer,
            Some((&ca, &ca_key)),
        );

        let outcome = evaluate(
            &leaf,
            &[anchor(github_root_ca(), "list:0"), anchor(&ca, "list:1")],
        )
        .await;
        // an anchor whose subject is not the chain's issuer is not tried
        let unnamed = evaluate(&leaf, &[anchor(github_root_ca(), "list:0")]).await;

        assert_eq!(outcome.status, IssuerTrustStatus::Trusted);
        assert_eq!(outcome.source_ref.as_deref(), Some("list:1"));
        assert_eq!(unnamed.reason, Some(IssuerTrustReason::NoAnchorMatch));
    }

    #[test]
    fn did_issuer_is_never_rejected() {
        let outcome = IssuerTrustOutcome::not_evaluated(IssuerTrustReason::DidIssuer);
        assert!(!outcome.rejected_when_enforced());
    }

    mod revocation {
        use one_core::proto::certificate_validator::Error;

        use super::*;

        async fn evaluate_result(
            chain: &str,
            anchors: &[TrustAnchor],
        ) -> Result<IssuerTrustOutcome, Error> {
            evaluate_chain(&CertificateValidatorImpl::default(), chain, anchors).await
        }

        #[tokio::test]
        async fn a_chain_reaching_no_anchor_is_not_checked_for_revocation() {
            let pki = CrlPki::start().await;
            let crl = pki.serve_crl(true).await;

            let outcome = evaluate_result(&pki.issuer, &[anchor(github_root_ca(), "list:1")])
                .await
                .unwrap();

            assert_eq!(outcome.reason, Some(IssuerTrustReason::NoAnchorMatch));
            crl.assert_calls_async(0).await;
        }

        #[tokio::test]
        async fn a_chain_reaching_an_anchor_is_checked_for_revocation() {
            let pki = CrlPki::start().await;
            let crl = pki.serve_crl(false).await;

            let outcome = evaluate_result(&pki.issuer, &[anchor(&pki.ca, "list:1")])
                .await
                .unwrap();

            assert_eq!(outcome.status, IssuerTrustStatus::Trusted);
            crl.assert_calls_async(1).await;
        }

        #[tokio::test]
        async fn a_revoked_issuer_under_an_anchor_is_an_error() {
            let pki = CrlPki::start().await;
            pki.serve_crl(true).await;

            let result = evaluate_result(&pki.issuer, &[anchor(&pki.ca, "list:1")]).await;

            assert!(
                matches!(result, Err(Error::CertificateRevoked)),
                "{result:?}"
            );
        }

        #[tokio::test]
        async fn an_anchor_inside_the_chain_checks_the_certificates_under_it() {
            let pki = CrlPki::start().await;
            pki.serve_crl(true).await;
            let chain = format!("{}{}", pki.issuer, pki.ca);

            let result = evaluate_result(&chain, &[anchor(&pki.ca, "list:1")]).await;

            assert!(
                matches!(result, Err(Error::CertificateRevoked)),
                "{result:?}"
            );
        }

        #[tokio::test]
        async fn a_rejected_path_gives_way_to_another_anchor() {
            let pki = CrlPki::start().await;
            pki.serve_crl(true).await;
            let chain = format!("{}{}", pki.issuer, pki.ca);
            // the issuer certificate is itself listed by a later anchor
            let issuer_only = anchor(&pki.issuer, "list:2");

            let outcome = evaluate_result(&chain, &[anchor(&pki.ca, "list:1"), issuer_only])
                .await
                .unwrap();

            assert_eq!(outcome.source_ref.as_deref(), Some("list:2"));
        }
    }

    mod sd_jwt {
        use one_core::mapper::x509::pem_chain_into_x5c;

        use super::*;
        use crate::http::MockHttpClient;
        use crate::nonce::Nonce;
        use crate::utils::test_utils::anchors;
        use crate::utils::x509_truststore::tests::presentation;
        use crate::vc::Presentation;
        use crate::vc::core::{HolderBinder, VerificationParams, Verifier, VerifierService};

        const NONCE: &str = "issuer-trust-nonce";

        fn sd_jwt_vc() -> String {
            sd_jwt_vc_under(test_issuer_cert())
        }

        /// Presentation of a credential signed by the fixture issuer key under `chain`.
        fn sd_jwt_vc_under(chain: &str) -> String {
            let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
            presentation(
                Some(pem_chain_into_x5c(chain).unwrap()),
                now - 60,
                now + 3600,
                &[],
                &[],
                NONCE,
            )
        }

        async fn verify(
            vp: String,
            mode: IssuerTrustMode,
            anchor_pems: &[&str],
        ) -> crate::vc::core::Result<(crate::vc::claims::Claims, IssuerTrustOutcome)> {
            verify_with_chain(vp, mode, anchor_pems)
                .await
                .map(|verified| (verified.claims, verified.outcome))
        }

        async fn verify_with_chain(
            vp: String,
            mode: IssuerTrustMode,
            anchor_pems: &[&str],
        ) -> crate::vc::core::Result<IssuerTrustVerification> {
            let trust_anchors = anchor_pems
                .iter()
                .map(|pem| anchor(pem, "list:1"))
                .collect();
            verify_with_anchors(vp, mode, trust_anchors).await
        }

        /// Verifies with `trust_anchors`, also passed as trusted certificates (as the OID4VP builder does).
        async fn verify_with_anchors(
            vp: String,
            mode: IssuerTrustMode,
            trust_anchors: Vec<TrustAnchor>,
        ) -> crate::vc::core::Result<IssuerTrustVerification> {
            let pems: Vec<&str> = trust_anchors.iter().map(|a| a.pem.as_str()).collect();
            let service = VerifierService::new("verifier", Default::default())
                .with_verification_params(VerificationParams {
                    trusted_certs: Some(anchors(&pems)),
                    issuer_trust: Some(IssuerTrustConfig {
                        mode,
                        anchors: trust_anchors.clone(),
                        ..Default::default()
                    }),
                });
            service
                .verify_presentation_with_issuer_trust(
                    Some(HolderBinder {
                        nonce: Nonce::from_secret(NONCE.to_string()),
                        verifier_id: "x509_san_dns:verifier-asdk".to_string(),
                        response_uri: None,
                    }),
                    &Presentation::SdJwtVp(vp),
                    &MockHttpClient::new(),
                )
                .await
        }

        #[tokio::test]
        async fn issuer_under_an_anchor_is_trusted() {
            let (_, outcome) = verify(sd_jwt_vc(), IssuerTrustMode::Enforce, &[test_root_ca()])
                .await
                .unwrap();
            assert_eq!(outcome.status, IssuerTrustStatus::Trusted);
            assert_eq!(outcome.source_ref.as_deref(), Some("list:1"));
        }

        #[tokio::test]
        async fn a_pid_is_classified_and_trusted_under_a_pid_provider() {
            let (claims, outcome) =
                verify(sd_jwt_vc(), IssuerTrustMode::Enforce, &[test_root_ca()])
                    .await
                    .unwrap();

            assert_eq!(
                claims.get("vct").and_then(|vct| vct.as_str()),
                Some("urn:eudi:pid:1")
            );
            assert_eq!(outcome.category, Some(CredentialCategory::Pid));
            assert_eq!(outcome.role.as_deref(), Some("pid_provider"));
        }

        #[tokio::test]
        async fn a_pid_under_a_qeaa_provider_is_untrusted() {
            for role in ["qeaa_provider", "eaa_provider"] {
                let qeaa_anchor = TrustAnchor {
                    role: Some(role.to_string()),
                    ..anchor(test_root_ca(), "list:1")
                };

                let verified =
                    verify_with_anchors(sd_jwt_vc(), IssuerTrustMode::Report, vec![qeaa_anchor])
                        .await
                        .unwrap();

                assert_eq!(
                    verified.outcome,
                    IssuerTrustOutcome {
                        category: Some(CredentialCategory::Pid),
                        ..IssuerTrustOutcome::untrusted(IssuerTrustReason::NoAnchorsForCategory)
                    }
                );
            }
        }

        #[tokio::test]
        async fn trusted_certificates_alone_anchor_a_pid() {
            // without an issuer trust config, the trusted certificates are role-less anchors
            let service = VerifierService::new("verifier", Default::default())
                .with_verification_params(VerificationParams {
                    trusted_certs: Some(anchors(&[test_root_ca()])),
                    issuer_trust: None,
                });

            let verified = service
                .verify_presentation_with_issuer_trust(
                    Some(HolderBinder {
                        nonce: Nonce::from_secret(NONCE.to_string()),
                        verifier_id: "x509_san_dns:verifier-asdk".to_string(),
                        response_uri: None,
                    }),
                    &Presentation::SdJwtVp(sd_jwt_vc()),
                    &MockHttpClient::new(),
                )
                .await
                .unwrap();

            assert_eq!(verified.outcome.status, IssuerTrustStatus::Trusted);
            assert_eq!(verified.outcome.category, Some(CredentialCategory::Pid));
        }

        #[tokio::test]
        async fn issuer_under_no_anchor_is_untrusted_but_still_verified() {
            for mode in [IssuerTrustMode::Enforce, IssuerTrustMode::Report] {
                let (_, outcome) = verify(sd_jwt_vc(), mode, &[github_root_ca()])
                    .await
                    .unwrap();
                assert_eq!(outcome.reason, Some(IssuerTrustReason::NoAnchorMatch));
                assert!(outcome.rejected_when_enforced());
            }
        }

        #[tokio::test]
        async fn forged_issuer_signature_fails_under_report() {
            // swap the issuer JWT's payload; its signature no longer verifies
            let vp = sd_jwt_vc();
            let mut parts: Vec<String> = vp.split('~').map(str::to_string).collect();
            let mut jwt: Vec<String> = parts[0].split('.').map(str::to_string).collect();
            let other = sd_jwt_vc();
            let other_payload = other.split('~').next().unwrap().split('.').nth(1).unwrap();
            jwt[1] = format!("{}x", &other_payload[..other_payload.len() - 1]);
            parts[0] = jwt.join(".");

            let result = verify(parts.join("~"), IssuerTrustMode::Report, &[]).await;

            assert!(result.is_err());
        }

        #[tokio::test]
        async fn issuer_with_a_crl_and_no_anchor_match_is_verified_under_report() {
            // regression: the integrity check must not fetch the CRL of an unanchored chain
            let pki = CrlPki::start().await;
            let crl = pki.serve_crl(false).await;

            let (_, outcome) = verify(
                sd_jwt_vc_under(&pki.issuer),
                IssuerTrustMode::Report,
                &[github_root_ca()],
            )
            .await
            .unwrap();

            assert_eq!(outcome.reason, Some(IssuerTrustReason::NoAnchorMatch));
            crl.assert_calls_async(0).await;
        }

        #[tokio::test]
        async fn revoked_issuer_under_an_anchor_fails_in_both_modes() {
            let pki = CrlPki::start().await;
            pki.serve_crl(true).await;

            for mode in [IssuerTrustMode::Enforce, IssuerTrustMode::Report] {
                let result = verify(sd_jwt_vc_under(&pki.issuer), mode, &[&pki.ca]).await;

                let Err(crate::vc::core::Error::VC {
                    source: crate::vc::formats::Error::Verifying { details, .. },
                    ..
                }) = result
                else {
                    panic!("a revoked issuer must fail verification under {mode:?}");
                };
                assert!(details.contains("Certificate revoked"), "{details}");
            }
        }

        #[tokio::test]
        async fn issuer_under_an_anchor_and_not_revoked_is_trusted_with_one_crl_fetch() {
            let pki = CrlPki::start().await;
            let crl = pki.serve_crl(false).await;

            for _ in 0..2 {
                let (_, outcome) = verify(
                    sd_jwt_vc_under(&pki.issuer),
                    IssuerTrustMode::Enforce,
                    &[&pki.ca],
                )
                .await
                .unwrap();
                assert_eq!(outcome.status, IssuerTrustStatus::Trusted);
            }

            // integrity and issuer trust share one validator and its CRL cache
            crl.assert_calls_async(1).await;
        }

        #[tokio::test]
        async fn a_chain_reaching_only_a_revocation_service_is_untrusted_without_a_crl_fetch() {
            // regression: the integrity pre-check must use issuer anchors only
            let pki = CrlPki::start().await;
            let unreachable_crl = pki
                .server
                .mock_async(|when, then| {
                    when.any_request();
                    then.status(503);
                })
                .await;
            let revocation_service = with_service_type(
                anchor(&pki.ca, "list:1"),
                "http://uri.etsi.org/19602/SvcType/PID/Revocation",
            );

            let verified = verify_with_anchors(
                sd_jwt_vc_under(&pki.issuer),
                IssuerTrustMode::Report,
                vec![revocation_service],
            )
            .await
            .unwrap();

            assert_eq!(
                verified.outcome.reason,
                Some(IssuerTrustReason::NoAnchorMatch)
            );
            unreachable_crl.assert_calls_async(0).await;
        }

        /// Root → intermediate → issuer certificate (fixture key), the issuer optionally expired.
        fn three_tier_pki(expired: bool) -> (String, String, String) {
            let root_key = test_fixtures::JWK::generate_p256();
            let root = test_fixtures::x509(
                &serde_json::json!({
                    "subject": [["CN", "Three-tier Root"]],
                    "ca": true, "key_usages": ["key_cert_sign", "crl_sign"]
                }),
                &root_key,
                None,
            );
            let intermediate_key = test_fixtures::JWK::generate_p256();
            let intermediate = test_fixtures::x509(
                &serde_json::json!({
                    "subject": [["CN", "Three-tier Intermediate"]],
                    "ca": true, "key_usages": ["key_cert_sign", "crl_sign"],
                    "authority_key_identifier": true
                }),
                &intermediate_key,
                Some((&root, &root_key)),
            );
            let (not_before, not_after) = if expired {
                ("2020-01-01", "2021-01-01")
            } else {
                ("2026-01-01", "2046-01-01")
            };
            let issuer = test_fixtures::x509(
                &serde_json::json!({
                    "subject": [["CN", "Three-tier Issuer"]], "sans": ["issuer.example"],
                    "not_before": not_before, "not_after": not_after,
                    "key_usages": ["digital_signature"], "authority_key_identifier": true
                }),
                &test_fixtures::keys().issuer,
                Some((&intermediate, &intermediate_key)),
            );
            (root, intermediate, issuer)
        }

        #[tokio::test]
        async fn issuer_under_a_listed_intermediate_left_out_of_x5c_is_trusted() {
            // a trust list may list the intermediate CA; HAIP keeps the anchor out of `x5c`
            let (root, intermediate, issuer) = three_tier_pki(false);

            for mode in [IssuerTrustMode::Enforce, IssuerTrustMode::Report] {
                let (_, outcome) = verify(sd_jwt_vc_under(&issuer), mode, &[&intermediate])
                    .await
                    .unwrap();
                assert_eq!(outcome.status, IssuerTrustStatus::Trusted, "{mode:?}");
            }
            // a listed root is not reached when `x5c` leaves out the intermediate
            let (_, outcome) = verify(sd_jwt_vc_under(&issuer), IssuerTrustMode::Report, &[&root])
                .await
                .unwrap();
            assert_eq!(outcome.reason, Some(IssuerTrustReason::NoAnchorMatch));
        }

        /// The `aki` value a verifier requests for `anchor_pem`.
        fn requested_aki(anchor_pem: &str) -> crate::vc::trust::trusted_authorities::KeyIdentifier {
            crate::vc::trust::trusted_authorities::derive_trusted_authority_akis(&[anchor(
                anchor_pem, "list:1",
            )])
            .values
            .remove(0)
        }

        #[tokio::test]
        async fn issuer_chain_akis_name_the_intermediate_left_out_of_x5c() {
            use crate::vc::trust::trusted_authorities::matches_required_akis;

            let (root, intermediate, issuer) = three_tier_pki(false);

            let verified = verify_with_chain(
                sd_jwt_vc_under(&issuer),
                IssuerTrustMode::Report,
                &[&intermediate],
            )
            .await
            .unwrap();

            let chain_akis = verified.issuer_chain_akis.as_deref();
            assert!(chain_akis.is_some());
            assert!(matches_required_akis(
                &[&requested_aki(&intermediate)],
                chain_akis
            ));
            // the root names no certificate in `x5c`: requesting it alone misses
            assert!(!matches_required_akis(&[&requested_aki(&root)], chain_akis));
        }

        /// A PID signed by the fixture key, issued by its `did:key` (no chain).
        fn did_sd_jwt_vc() -> String {
            did_sd_jwt_vc_of("urn:eudi:pid:1")
        }

        /// A `vct` credential signed by the fixture key, issued by its `did:key`.
        fn did_sd_jwt_vc_of(vct: &str) -> String {
            let keys = test_fixtures::keys();
            let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
            let sd_jwt = test_fixtures::sd_jwt(
                &serde_json::json!({
                    "typ": "dc+sd-jwt", "alg": "ES256",
                    "kid": test_fixtures::did_key_url(&keys.issuer)
                }),
                &serde_json::json!({
                    "vct": vct,
                    "iss": test_fixtures::did_key(&keys.issuer),
                    "cnf": { "jwk": keys.holder.to_public() },
                    "exp": now + 3600,
                    "iat": now - 60
                }),
                &[],
                &keys.issuer,
            );
            test_fixtures::sd_jwt_kb(
                &sd_jwt,
                &serde_json::json!({ "typ": "kb+jwt", "alg": "ES256" }),
                &serde_json::json!({
                    "aud": "x509_san_dns:verifier-asdk", "iat": now - 60, "nonce": NONCE
                }),
                &keys.holder,
            )
        }

        #[tokio::test]
        async fn a_did_signed_pid_is_refused() {
            let verified =
                verify_with_chain(did_sd_jwt_vc(), IssuerTrustMode::Report, &[test_root_ca()])
                    .await
                    .unwrap();

            assert_eq!(
                verified.outcome,
                IssuerTrustOutcome {
                    category: Some(CredentialCategory::Pid),
                    ..IssuerTrustOutcome::untrusted(IssuerTrustReason::DidIssuerNotAllowed)
                }
            );
            assert!(verified.outcome.rejected_when_enforced());
        }

        #[tokio::test]
        async fn a_did_signed_eaa_is_not_evaluated_and_not_rejected() {
            let verified = verify_with_chain(
                did_sd_jwt_vc_of("https://example.com/diploma"),
                IssuerTrustMode::Enforce,
                &[test_root_ca()],
            )
            .await
            .unwrap();

            assert_eq!(
                verified.outcome,
                IssuerTrustOutcome {
                    category: Some(CredentialCategory::Eaa),
                    ..IssuerTrustOutcome::not_evaluated(IssuerTrustReason::DidIssuer)
                }
            );
            assert!(!verified.outcome.rejected_when_enforced());
        }

        #[tokio::test]
        async fn did_issuer_has_no_chain_and_matches_no_requested_authority() {
            use crate::vc::trust::trusted_authorities::matches_required_akis;

            let verified =
                verify_with_chain(did_sd_jwt_vc(), IssuerTrustMode::Report, &[test_root_ca()])
                    .await
                    .unwrap();

            assert_eq!(
                verified.outcome.reason,
                Some(IssuerTrustReason::DidIssuerNotAllowed)
            );
            assert_eq!(verified.issuer_chain_akis, None);
            assert!(!matches_required_akis(
                &[&requested_aki(test_root_ca())],
                verified.issuer_chain_akis.as_deref()
            ));
        }

        #[tokio::test]
        async fn expired_issuer_certificate_fails_under_report() {
            let (_, intermediate, issuer) = three_tier_pki(true);

            let result = verify(
                sd_jwt_vc_under(&issuer),
                IssuerTrustMode::Report,
                &[&intermediate],
            )
            .await;

            let error = format!("{:?}", result.expect_err("an expired issuer must fail"));
            assert!(error.contains("Certificate is expired"), "{error}");
        }

        #[tokio::test]
        async fn an_undecodable_issuer_jwt_fails_rather_than_passing_as_a_did_issuer() {
            // the SD-JWT verifier ignores an unknown `crit`, the issuer key decoder rejects it
            let vp = x5c_sd_jwt_vc_with(
                serde_json::json!({ "crit": ["x"], "x": true }),
                "urn:example:eaa:1",
            );
            let eaa_anchor = TrustAnchor {
                role: Some("eaa_provider".to_string()),
                ..anchor(github_root_ca(), "list:1")
            };

            let result = verify_with_anchors(vp, IssuerTrustMode::Enforce, vec![eaa_anchor]).await;

            let error = format!(
                "{:?}",
                result.expect_err("an undecodable issuer JWT must fail")
            );
            assert!(error.contains("Issuer JWT cannot be decoded"), "{error}");
        }

        #[test]
        fn issuer_key_source() {
            assert!(matches!(
                sd_jwt_issuer_key(&sd_jwt_vc()),
                Ok(SdJwtIssuerKey::X5c(_))
            ));
            assert_eq!(
                sd_jwt_issuer_key(&did_sd_jwt_vc()).unwrap(),
                SdJwtIssuerKey::Other
            );
        }

        #[rstest::rstest]
        #[case::not_a_jwt("not-a-jwt~".to_string())]
        #[case::unknown_crit_header(x5c_sd_jwt_vc_with(
            serde_json::json!({ "crit": ["x"], "x": true }),
            "urn:eudi:pid:1",
        ))]
        #[case::x5c_not_a_certificate(x5c_sd_jwt_vc_with(
            serde_json::json!({ "x5c": ["%not base64%"] }),
            "urn:eudi:pid:1",
        ))]
        fn an_issuer_key_that_cannot_be_read_is_an_error(#[case] vp: String) {
            assert!(sd_jwt_issuer_key(&vp).is_err());
        }

        /// A `vct` credential under the fixture `x5c` chain, with `extra_header` merged in.
        fn x5c_sd_jwt_vc_with(extra_header: serde_json::Value, vct: &str) -> String {
            let keys = test_fixtures::keys();
            let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
            let mut header = serde_json::json!({
                "typ": "dc+sd-jwt", "alg": "ES256",
                "x5c": pem_chain_into_x5c(test_issuer_cert()).unwrap()
            });
            if let (Some(header), Some(extra)) = (header.as_object_mut(), extra_header.as_object())
            {
                header.extend(extra.clone());
            }
            let sd_jwt = test_fixtures::sd_jwt(
                &header,
                &serde_json::json!({
                    "vct": vct,
                    "iss": "https://localhost.emobix.co.uk:9443/test/a/asdk-vci-verifier-test-asdk-598",
                    "cnf": { "jwk": keys.holder.to_public() },
                    "exp": now + 3600,
                    "iat": now - 60
                }),
                &[],
                &keys.issuer,
            );
            test_fixtures::sd_jwt_kb(
                &sd_jwt,
                &serde_json::json!({ "typ": "kb+jwt", "alg": "ES256" }),
                &serde_json::json!({
                    "aud": "x509_san_dns:verifier-asdk", "iat": now - 60, "nonce": NONCE
                }),
                &keys.holder,
            )
        }
    }
}
