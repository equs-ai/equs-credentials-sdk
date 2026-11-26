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
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
use one_core::provider::revocation::token_status_list::{
    IDENTIFIER_LIST_ENTRY_TYPE, IDENTIFIER_LIST_ID_KEY, IDENTIFIER_LIST_URI_KEY,
    MSO_STATUS_CERTIFICATE_KEY,
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
/// How far the MSO validity window may be off this clock.
pub(crate) const VALIDITY_LEEWAY: time::Duration = time::Duration::seconds(60);
/// id-mdl-kp-mdlDS, the Extended Key Usage of an mdoc Document Signer (ISO/IEC 18013-5 Annex B.1.4).
const MDL_DS_EKU: x509_parser::oid_registry::Oid<'static> =
    x509_parser::der_parser::oid!(1.0.18013.5.1.2);
const TOKEN_STATUS_LIST_ENTRY: &str = "TokenStatusListEntry";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MdocStatus {
    None,
    StatusList {
        uri: String,
        idx: usize,
        certificate: Option<Vec<u8>>,
    },
    IdentifierList {
        uri: String,
        id: CredentialId,
        certificate: Option<Vec<u8>>,
    },
    Unsupported(Vec<String>),
}

/// The MSO status and issuer chain of a presentation, read without verifying it.
#[derive(Debug)]
pub(crate) struct UnverifiedMdocStatus {
    pub status: MdocStatus,
    pub issuer_chain: Option<String>,
}

/// An mdoc's identifier in its Identifier List. It identifies the credential, so `Debug`
/// does not print it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CredentialId(pub(crate) Vec<u8>);

impl std::fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialId(<redacted>)")
    }
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
            // the caller evaluates the chain against its anchors
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
        // one-core 0.2.3 always identifies an mdoc issuer by its `x5chain`
        let document_signer_validity = match issuer_chain.as_deref() {
            Some(chain) => {
                check_document_signer_profile(chain)?;
                Some(document_signer_validity(chain)?)
            }
            None => None,
        };
        check_validity_info(
            &verified_claims,
            document_signer_validity,
            OffsetDateTime::now_utc(),
        )?;
        let status = MdocStatus::from_credential_status(&verified_claims.status)?;
        Ok(VerifiedMdoc {
            claims: verified_claims.try_into()?,
            issuer_chain,
            status,
        })
    }

    /// The first document's MSO status and issuer chain, read without verification.
    pub(crate) async fn status_unverified(
        presentation: &Presentation,
    ) -> Result<UnverifiedMdocStatus> {
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
        Ok(UnverifiedMdocStatus {
            status: MdocStatus::from_credential_status(&details.status)?,
            issuer_chain: match &details.issuer {
                IdentifierDetails::Certificate(certificate) => Some(certificate.chain.clone()),
                _ => None,
            },
        })
    }
}

/// Checks the Document Signer, the first certificate of `chain_pem`: it must not be a CA, and an
/// Extended Key Usage, if present, must list [MDL_DS_EKU].
fn check_document_signer_profile(chain_pem: &str) -> Result<()> {
    let rejected = |details: &str| {
        PresentationSnafu {
            details: format!("Document Signer certificate {details}"),
        }
        .build()
    };
    let pem = x509_parser::pem::Pem::iter_from_buffer(chain_pem.as_bytes())
        .next()
        .and_then(|pem| pem.ok())
        .ok_or_else(|| rejected("is missing"))?;
    let certificate = pem.parse_x509().map_err(|_| rejected("cannot be parsed"))?;

    // `basic_constraints()` reads an extension that does not parse as absent
    let malformed_basic_constraints = || rejected("has a malformed basic constraints extension");
    let is_ca = match certificate
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)
        .map_err(|_| malformed_basic_constraints())?
    {
        None => false,
        Some(extension) => match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::BasicConstraints(constraints) => {
                constraints.ca
            }
            _ => return Err(malformed_basic_constraints()),
        },
    };
    if is_ca {
        return Err(rejected("must not be a CA certificate"));
    }

    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|_| rejected("has a malformed extended key usage extension"))?;
    if let Some(extended_key_usage) = extended_key_usage
        && !extended_key_usage.value.other.contains(&MDL_DS_EKU)
    {
        return Err(rejected(
            "has an extended key usage without the mdoc Document Signer purpose 1.0.18013.5.1.2",
        ));
    }
    Ok(())
}

/// The `notBefore` and `notAfter` of the Document Signer, the first certificate of `chain_pem`.
fn document_signer_validity(chain_pem: &str) -> Result<(OffsetDateTime, OffsetDateTime)> {
    let rejected = |details: &str| {
        PresentationSnafu {
            details: format!("Document Signer certificate {details}"),
        }
        .build()
    };
    let pem = x509_parser::pem::Pem::iter_from_buffer(chain_pem.as_bytes())
        .next()
        .and_then(|pem| pem.ok())
        .ok_or_else(|| rejected("is missing"))?;
    let certificate = pem.parse_x509().map_err(|_| rejected("cannot be parsed"))?;
    let validity = certificate.validity();
    Ok((
        validity.not_before.to_datetime(),
        validity.not_after.to_datetime(),
    ))
}

/// Checks the MSO `validityInfo` (ISO/IEC 18013-5 §9.3.1): `signed` within the Document Signer's
/// validity, `validFrom` before `validUntil`, and `now` between them give or take
/// [VALIDITY_LEEWAY].
fn check_validity_info(
    credential: &DetailCredential,
    document_signer_validity: Option<(OffsetDateTime, OffsetDateTime)>,
    now: OffsetDateTime,
) -> Result<()> {
    let rejected = |details: &str| {
        PresentationSnafu {
            details: details.to_string(),
        }
        .fail()
    };
    let (Some(signed), Some(valid_from), Some(valid_until)) = (
        credential.issuance_date,
        credential.valid_from,
        credential.valid_until,
    ) else {
        return rejected("MSO validity info is incomplete");
    };
    if let Some((not_before, not_after)) = document_signer_validity
        && !(not_before..=not_after).contains(&signed)
    {
        return rejected("MSO `signed` is not within the Document Signer certificate's validity");
    }
    if valid_from >= valid_until {
        return rejected("MSO `validFrom` is not earlier than `validUntil`");
    }
    if valid_from > now + VALIDITY_LEEWAY {
        return rejected("Credential is not yet valid");
    }
    // the leeway goes on `now`: an MSO date near year 9999 plus the leeway would overflow
    if valid_until < now - VALIDITY_LEEWAY {
        return rejected("Credential has expired");
    }
    Ok(())
}

impl MdocStatus {
    /// The MSO status to check: `status_list` first, else `identifier_list`.
    fn from_credential_status(entries: &[CredentialStatus]) -> Result<Self> {
        if entries.is_empty() {
            return Ok(Self::None);
        }
        let mechanisms: Vec<&str> = entries.iter().map(|entry| entry.r#type.as_str()).collect();
        let find = |r#type: &str| entries.iter().find(|entry| entry.r#type == r#type);
        if let Some(status_list) = find(TOKEN_STATUS_LIST_ENTRY) {
            if mechanisms.len() > 1 {
                info!(
                    ?mechanisms,
                    "mdoc status mechanisms other than status_list not checked"
                );
            }
            return Self::status_list(status_list);
        }
        if let Some(identifier_list) = find(IDENTIFIER_LIST_ENTRY_TYPE) {
            if mechanisms.len() > 1 {
                info!(
                    ?mechanisms,
                    "mdoc status mechanisms other than identifier_list not checked"
                );
            }
            return Self::identifier_list(identifier_list);
        }
        Ok(Self::Unsupported(
            mechanisms.into_iter().map(str::to_owned).collect(),
        ))
    }

    fn identifier_list(entry: &CredentialStatus) -> Result<Self> {
        let malformed = || {
            PresentationSnafu {
                details: "Malformed mso_mdoc identifier_list".to_string(),
            }
            .build()
        };
        let field = |name: &str| {
            entry
                .additional_fields
                .get(name)
                .and_then(serde_json::Value::as_str)
        };
        let id = field(IDENTIFIER_LIST_ID_KEY).and_then(|id| URL_SAFE_NO_PAD.decode(id).ok());
        let certificate = list_certificate(entry).ok_or_else(malformed)?;
        match (field(IDENTIFIER_LIST_URI_KEY), id) {
            (Some(uri), Some(id)) if !id.is_empty() => Ok(Self::IdentifierList {
                uri: uri.to_string(),
                id: CredentialId(id),
                certificate,
            }),
            _ => Err(malformed()),
        }
    }

    fn status_list(status_list: &CredentialStatus) -> Result<Self> {
        let malformed = || {
            PresentationSnafu {
                details: "Malformed mso_mdoc status_list".to_string(),
            }
            .build()
        };
        let field = |name: &str| {
            status_list
                .additional_fields
                .get(name)
                .and_then(serde_json::Value::as_str)
        };
        let certificate = list_certificate(status_list).ok_or_else(malformed)?;
        match (field("uri"), field("idx").and_then(|idx| idx.parse().ok())) {
            (Some(uri), Some(idx)) => Ok(Self::StatusList {
                uri: uri.to_string(),
                idx,
                certificate,
            }),
            _ => Err(malformed()),
        }
    }

    /// The MSO `certificate` of the list, the trust anchor of its `x5chain`.
    pub(crate) fn certificate(&self) -> Option<&[u8]> {
        match self {
            Self::StatusList { certificate, .. } | Self::IdentifierList { certificate, .. } => {
                certificate.as_deref()
            }
            Self::None | Self::Unsupported(_) => None,
        }
    }
}

/// `Some(None)` without a `certificate`, `Some(Some(der))` with one, none if it is not base64url.
fn list_certificate(entry: &CredentialStatus) -> Option<Option<Vec<u8>>> {
    match entry.additional_fields.get(MSO_STATUS_CERTIFICATE_KEY) {
        None => Some(None),
        Some(value) => value
            .as_str()
            .and_then(|der| URL_SAFE_NO_PAD.decode(der).ok())
            .filter(|der| !der.is_empty())
            .map(Some),
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
                "key_usages": ["digital_signature"], "extended_key_usages": ["mdl_ds"]
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

    /// A presentation with MSO `status`, issuer-signed by `ds_key` under `x5chain`.
    pub fn sample_mso_mdoc_vp_with_status_under(
        x5chain: &str,
        ds_key: &test_fixtures::JWK,
        status: serde_json::Value,
    ) -> String {
        mdoc_vp_under(x5chain, ds_key, None, None, Some(status))
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
            &mdoc_spec(x5chain, response_uri, verifier_key, status),
            ds_key,
            &test_fixtures::keys().holder,
        )
    }

    /// The `test_fixtures::mdoc` spec of the sample mDL, valid 2026-01-01 to 2046-01-01.
    fn mdoc_spec(
        x5chain: &str,
        response_uri: Option<&str>,
        verifier_key: Option<&test_fixtures::JWK>,
        status: Option<serde_json::Value>,
    ) -> serde_json::Value {
        serde_json::json!({
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
        })
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

    /// A presentation like [sample_mso_mdoc_vp], issuer-signed by `ds_key` under `x5chain`.
    pub fn sample_mso_mdoc_vp_under(x5chain: &str, ds_key: &test_fixtures::JWK) -> String {
        mdoc_vp_under(x5chain, ds_key, None, None, None)
    }

    /// MSO `validityInfo` checks.
    mod validity_info {
        use super::{binder, mdoc_spec};
        use crate::did::universal::UniversalResolver;
        use crate::utils::test_utils::{anchors, mdl_chain};
        use crate::vc::formats::mso_mdoc::{MsoMdocAPI, Presentation, VerifiedMdoc};
        use crate::vc::formats::{AnchorPolicy, VerifyOptions};
        use rstest::rstest;
        use time::format_description::well_known::Rfc3339;
        use time::{Duration, OffsetDateTime};

        /// `now` moved by `seconds`, as a `YYYY-MM-DDThh:mm:ssZ` date.
        fn from_now(seconds: i64) -> String {
            (OffsetDateTime::now_utc() + Duration::seconds(seconds))
                .replace_nanosecond(0)
                .unwrap()
                .format(&Rfc3339)
                .unwrap()
        }

        /// The sample mDL under a fresh IACA → DS chain (DS valid 2026-01-01 to 2046-01-01),
        /// with `signed` = `valid_from`, verified against that IACA.
        async fn verify(
            valid_from: &str,
            valid_until: &str,
        ) -> crate::vc::formats::Result<VerifiedMdoc> {
            let (iaca, ds, ds_key) = mdl_chain();
            let mut spec = mdoc_spec(&ds, None, None, None);
            spec["valid_from"] = valid_from.into();
            spec["valid_until"] = valid_until.into();
            let vp = test_fixtures::mdoc(&spec, &ds_key, &test_fixtures::keys().holder);
            MsoMdocAPI::verify_vp_with_issuer(
                &Presentation {
                    value: vp,
                    enc_pub_key: None,
                },
                Some(binder(None)),
                VerifyOptions {
                    trusted_certs: Some(anchors(&[&iaca])),
                    selective_claims: None,
                    anchor_policy: AnchorPolicy::Require,
                },
                UniversalResolver::default(),
            )
            .await
        }

        async fn error(valid_from: &str, valid_until: &str) -> String {
            format!("{:?}", verify(valid_from, valid_until).await.unwrap_err())
        }

        #[rstest]
        #[case::valid_from_within_the_leeway(from_now(30), "2046-01-01T00:00:00Z".to_string())]
        #[case::valid_until_within_the_leeway("2026-01-01T00:00:00Z".to_string(), from_now(-30))]
        #[tokio::test]
        async fn dates_within_a_minute_of_now_pass(
            #[case] valid_from: String,
            #[case] valid_until: String,
        ) {
            verify(&valid_from, &valid_until).await.unwrap();
        }

        #[tokio::test]
        async fn valid_until_at_the_end_of_time_passes() {
            // `validUntil` + the leeway is beyond what `OffsetDateTime` holds
            verify("2026-01-01T00:00:00Z", "9999-12-31T23:59:59Z")
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn valid_from_beyond_the_leeway_is_not_yet_valid() {
            let error = error(&from_now(120), "2046-01-01T00:00:00Z").await;

            assert!(error.contains("Credential is not yet valid"), "{error}");
        }

        #[tokio::test]
        async fn valid_until_beyond_the_leeway_has_expired() {
            let error = error("2026-01-01T00:00:00Z", &from_now(-120)).await;

            assert!(error.contains("Credential has expired"), "{error}");
        }

        #[tokio::test]
        async fn valid_from_after_valid_until_is_rejected() {
            let error = error("2026-06-01T00:00:00Z", "2026-03-01T00:00:00Z").await;

            assert!(error.contains("not earlier than `validUntil`"), "{error}");
        }

        #[tokio::test]
        async fn signed_before_the_document_signer_was_valid_is_rejected() {
            // the fixture sets `signed` to `valid_from`; the DS is valid from 2026-01-01
            let error = error("2025-06-01T00:00:00Z", "2046-01-01T00:00:00Z").await;

            assert!(error.contains("`signed` is not within"), "{error}");
        }
    }

    /// Document Signer certificate profile checks.
    mod document_signer {
        use super::{binder, sample_mso_mdoc_vp_under};
        use crate::did::universal::UniversalResolver;
        use crate::utils::test_utils::anchors;
        use crate::vc::formats::mso_mdoc::{MsoMdocAPI, Presentation, VerifiedMdoc};
        use crate::vc::formats::{AnchorPolicy, VerifyOptions};
        use rstest::rstest;
        use serde_json::{Value, json};

        /// An IACA (`C=US`), a DS it issued under `ds_spec` (merged into a `digital_signature`
        /// leaf with an authority key identifier), and a presentation signed under that DS.
        fn presentation_under(ds_spec: Value) -> (String, String) {
            let iaca_key = test_fixtures::JWK::generate_p256();
            let iaca = test_fixtures::x509(
                &json!({
                    "subject": [["CN", "Test IACA"], ["C", "US"]],
                    "not_before": "2026-01-01", "not_after": "2046-01-01",
                    "ca": true, "key_usages": ["key_cert_sign", "crl_sign"]
                }),
                &iaca_key,
                None,
            );
            let mut spec = json!({
                "subject": [["CN", "Test DS"], ["C", "US"]],
                "not_before": "2026-01-01", "not_after": "2046-01-01",
                "key_usages": ["digital_signature"], "authority_key_identifier": true
            });
            for (name, value) in ds_spec.as_object().unwrap() {
                spec[name] = value.clone();
            }
            let ds_key = test_fixtures::JWK::generate_p256();
            let ds = test_fixtures::x509(&spec, &ds_key, Some((&iaca, &iaca_key)));
            (sample_mso_mdoc_vp_under(&ds, &ds_key), iaca)
        }

        async fn verify(
            (vp, iaca): (String, String),
            policy: AnchorPolicy,
        ) -> crate::vc::formats::Result<VerifiedMdoc> {
            let trusted_certs = match policy {
                AnchorPolicy::Require => Some(anchors(&[&iaca])),
                AnchorPolicy::IntegrityOnly => None,
            };
            MsoMdocAPI::verify_vp_with_issuer(
                &Presentation {
                    value: vp,
                    enc_pub_key: None,
                },
                Some(binder(None)),
                VerifyOptions {
                    trusted_certs,
                    selective_claims: None,
                    anchor_policy: policy,
                },
                UniversalResolver::default(),
            )
            .await
        }

        #[rstest]
        #[case::require_server_auth(AnchorPolicy::Require, json!(["server_auth"]))]
        #[case::require_client_auth(AnchorPolicy::Require, json!(["client_auth"]))]
        #[case::integrity_only_server_auth(AnchorPolicy::IntegrityOnly, json!(["server_auth"]))]
        #[case::integrity_only_client_auth(AnchorPolicy::IntegrityOnly, json!(["client_auth"]))]
        #[tokio::test]
        async fn signer_with_another_extended_key_usage_is_rejected(
            #[case] policy: AnchorPolicy,
            #[case] ekus: Value,
        ) {
            let presentation = presentation_under(json!({ "extended_key_usages": ekus }));

            let error = format!("{:?}", verify(presentation, policy).await.unwrap_err());

            assert!(error.contains("1.0.18013.5.1.2"), "{error}");
        }

        #[rstest]
        #[case::require_mdl_ds(AnchorPolicy::Require, json!({ "extended_key_usages": ["mdl_ds"] }))]
        #[case::integrity_only_mdl_ds(AnchorPolicy::IntegrityOnly, json!({ "extended_key_usages": ["mdl_ds"] }))]
        #[case::among_other_usages(AnchorPolicy::Require, json!({ "extended_key_usages": ["server_auth", "mdl_ds"] }))]
        #[case::require_no_eku(AnchorPolicy::Require, json!({}))]
        #[case::integrity_only_no_eku(AnchorPolicy::IntegrityOnly, json!({}))]
        #[case::other_country_than_its_iaca(AnchorPolicy::Require, json!({
            "subject": [["CN", "Test DS"], ["C", "DE"]], "extended_key_usages": ["mdl_ds"]
        }))]
        #[tokio::test]
        async fn signer_with_the_ds_profile_passes(
            #[case] policy: AnchorPolicy,
            #[case] ds_spec: Value,
        ) {
            verify(presentation_under(ds_spec), policy).await.unwrap();
        }

        #[test]
        fn signer_with_a_malformed_basic_constraints_extension_is_rejected() {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            // an INTEGER where the BasicConstraints SEQUENCE belongs
            params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 19],
                vec![0x02, 0x01, 0x01],
            )];
            let key = rcgen::KeyPair::generate().unwrap();
            let pem = params.self_signed(&key).unwrap().pem();

            let error = format!(
                "{:?}",
                crate::vc::formats::mso_mdoc::check_document_signer_profile(&pem).unwrap_err()
            );

            assert!(error.contains("malformed basic constraints"), "{error}");
        }

        #[rstest]
        #[case::require(AnchorPolicy::Require)]
        #[case::integrity_only(AnchorPolicy::IntegrityOnly)]
        #[tokio::test]
        async fn signer_that_is_a_ca_is_rejected(#[case] policy: AnchorPolicy) {
            let presentation = presentation_under(json!({
                "ca": true,
                "key_usages": ["digital_signature", "key_cert_sign"],
                "extended_key_usages": ["mdl_ds"]
            }));

            let error = format!("{:?}", verify(presentation, policy).await.unwrap_err());

            assert!(error.contains("must not be a CA"), "{error}");
        }
    }

    mod status {
        use crate::vc::formats::mso_mdoc::{CredentialId, MdocStatus};
        use one_core::provider::credential_formatter::model::CredentialStatus;
        use rstest::rstest;
        use serde_json::json;
        use std::collections::HashMap;

        const URI: &str = "https://status.example/identifiers/1";

        fn entry(r#type: &str, fields: serde_json::Value) -> CredentialStatus {
            CredentialStatus {
                id: None,
                r#type: r#type.to_string(),
                status_purpose: None,
                additional_fields: serde_json::from_value::<HashMap<_, _>>(fields).unwrap(),
            }
        }

        fn identifier_list(fields: serde_json::Value) -> CredentialStatus {
            entry("identifier_list", fields)
        }

        #[test]
        fn identifier_list_is_read_with_its_decoded_id() {
            let status = MdocStatus::from_credential_status(&[identifier_list(
                json!({ "uri": URI, "id": "NjQ4Mg" }),
            )])
            .unwrap();

            assert_eq!(
                status,
                MdocStatus::IdentifierList {
                    uri: URI.to_string(),
                    id: CredentialId(b"6482".to_vec()),
                    certificate: None,
                }
            );
        }

        #[test]
        fn identifier_list_beside_an_unknown_mechanism_is_read() {
            let status = MdocStatus::from_credential_status(&[
                entry("future_list", json!({})),
                identifier_list(json!({ "uri": URI, "id": "NjQ4Mg" })),
            ])
            .unwrap();

            assert!(matches!(status, MdocStatus::IdentifierList { .. }));
        }

        #[test]
        fn status_list_wins_over_an_identifier_list() {
            let status = MdocStatus::from_credential_status(&[
                identifier_list(json!({ "uri": URI, "id": "NjQ4Mg" })),
                entry("TokenStatusListEntry", json!({ "uri": URI, "idx": "3" })),
            ])
            .unwrap();

            assert_eq!(
                status,
                MdocStatus::StatusList {
                    uri: URI.to_string(),
                    idx: 3,
                    certificate: None,
                }
            );
        }

        #[rstest]
        #[case::type_only(json!({}))]
        #[case::no_uri(json!({ "id": "NjQ4Mg" }))]
        #[case::no_id(json!({ "uri": URI }))]
        #[case::empty_id(json!({ "uri": URI, "id": "" }))]
        #[case::padded_id(json!({ "uri": URI, "id": "NjQ4Mg==" }))]
        #[case::standard_alphabet(json!({ "uri": URI, "id": "+/8B" }))]
        #[case::not_base64(json!({ "uri": URI, "id": "6482!" }))]
        #[case::id_not_a_string(json!({ "uri": URI, "id": 6482 }))]
        #[case::certificate_not_base64url(json!({ "uri": URI, "id": "NjQ4Mg", "certificate": "MII+" }))]
        #[case::empty_certificate(json!({ "uri": URI, "id": "NjQ4Mg", "certificate": "" }))]
        #[case::certificate_not_a_string(json!({ "uri": URI, "id": "NjQ4Mg", "certificate": 1 }))]
        fn malformed_identifier_list_is_rejected(#[case] fields: serde_json::Value) {
            let error = MdocStatus::from_credential_status(&[identifier_list(fields)])
                .unwrap_err()
                .to_string();

            assert!(
                error.contains("Malformed mso_mdoc identifier_list"),
                "unexpected error: {error}"
            );
        }

        #[test]
        fn status_list_certificate_is_read() {
            let status = MdocStatus::from_credential_status(&[entry(
                "TokenStatusListEntry",
                json!({ "uri": URI, "idx": "3", "certificate": "MIIB" }),
            )])
            .unwrap();

            assert_eq!(status.certificate(), Some([0x30, 0x82, 0x01].as_slice()));
        }

        #[test]
        fn identifier_list_certificate_is_read() {
            let status = MdocStatus::from_credential_status(&[identifier_list(
                json!({ "uri": URI, "id": "NjQ4Mg", "certificate": "MIIB" }),
            )])
            .unwrap();

            assert_eq!(status.certificate(), Some([0x30, 0x82, 0x01].as_slice()));
        }

        #[test]
        fn status_list_with_a_malformed_certificate_is_rejected() {
            let error = MdocStatus::from_credential_status(&[entry(
                "TokenStatusListEntry",
                json!({ "uri": URI, "idx": "3", "certificate": "MII+" }),
            )])
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("Malformed mso_mdoc status_list"),
                "unexpected error: {error}"
            );
        }

        #[test]
        fn debug_does_not_print_the_identifier() {
            let status = MdocStatus::IdentifierList {
                uri: URI.to_string(),
                id: CredentialId(b"6482".to_vec()),
                certificate: None,
            };

            let debug = format!("{status:?}");

            assert!(debug.contains("<redacted>"), "{debug}");
            assert!(!debug.contains("54, 52, 56, 50"), "{debug}");
            assert!(!debug.contains("6482"), "{debug}");
        }
    }
}
