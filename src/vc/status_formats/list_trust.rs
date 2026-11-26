//! Which certificate a revocation list's `x5chain` must chain to.
//!
//! An mdoc list has exactly one anchor: the MSO status `certificate`, else the certificate that
//! signed the top of the MSO's `x5chain` (ISO/IEC 18013-5 2nd ed. §12.3.6.2; Regulation (EU)
//! 2024/2979 Annex II, EAA-6.2.10.1-06). Other lists accept any trusted anchor.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;

use crate::vc::formats::AnchorPolicy;
use crate::vc::formats::mso_mdoc::VALIDITY_LEEWAY;
use crate::vc::status_formats::{Result, VCStatusSnafu};

/// Map key for an anchor without a Subject Key Identifier.
const ANCHOR_WITHOUT_SKI: &str = "list-anchor";

/// How a list's `x5chain` is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ListTrust {
    /// The chain must reach this anchor, and no other.
    Anchor { ski: String, pem: String },
    /// Integrity only, with the chain top issued under the same name and Authority Key
    /// Identifier as the Document Signer chain's top. A label match, not a signature check: only
    /// for an untrusted issuer under `report`.
    SameIssuerAs(IssuerName),
    /// Any of `anchors` under `policy`, for lists that are not an mdoc's.
    AnyOf {
        anchors: HashMap<String, String>,
        policy: AnchorPolicy,
    },
}

/// The issuer of a certificate: its raw distinguished name and Authority Key Identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuerName {
    name: Vec<u8>,
    authority_key_id: Option<String>,
}

impl ListTrust {
    /// For a trusted mdoc issuer: the MSO `certificate`, else the anchor that signed the top of
    /// `issuer_chain`, else the held certificate of `issuer_chain` nearest its top. For an
    /// unverified MSO, the `certificate` must be one of `anchors`.
    pub(crate) fn mdoc_anchored(
        certificate: Option<&[u8]>,
        issuer_chain: Option<&str>,
        anchors: &[impl AsRef<str>],
        mso_verified: bool,
        now: OffsetDateTime,
    ) -> Result<Self> {
        let held: Vec<Vec<u8>> = anchors
            .iter()
            .filter_map(|pem| first_der(pem.as_ref()))
            .collect();
        if let Some(certificate) = certificate {
            if !mso_verified && !held.iter().any(|der| der.as_slice() == certificate) {
                return untrusted(
                    "the MSO status `certificate` of an unverified credential is not a trusted anchor",
                );
            }
            return Self::from_certificate(certificate, now);
        }
        let chain = chain_ders(issuer_chain)?;
        let top_der = chain.last().ok_or_else(no_issuer_chain)?;
        let top = parse(top_der)?;
        if let Some(signer) = signer_of(&top, &held, now) {
            return Self::from_der(signer);
        }
        if let Some(in_chain) = chain.iter().rev().find(|der| held.contains(der)) {
            return Self::from_der(in_chain);
        }
        untrusted("no trusted anchor signed the issuer's Document Signer chain")
    }

    /// For an untrusted mdoc issuer under `report`: the MSO `certificate`, else the top of
    /// `issuer_chain` when it is a self-signed CA, else that top's issuer name.
    pub(crate) fn mdoc_integrity_only(
        certificate: Option<&[u8]>,
        issuer_chain: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Self> {
        if let Some(certificate) = certificate {
            return Self::from_certificate(certificate, now);
        }
        let chain = chain_ders(issuer_chain)?;
        let top_der = chain.last().ok_or_else(no_issuer_chain)?;
        let top = parse(top_der)?;
        if top.is_ca() && top.subject() == top.issuer() && top.verify_signature(None).is_ok() {
            return Self::from_der(top_der);
        }
        Ok(Self::SameIssuerAs(IssuerName::of(&top)?))
    }

    /// The MSO `certificate`: it must be within its validity period and have a Subject Key
    /// Identifier.
    fn from_certificate(der: &[u8], now: OffsetDateTime) -> Result<Self> {
        let certificate = parse(der)?;
        if !within_validity(&certificate, now) {
            return untrusted("the MSO status `certificate` is outside its validity period");
        }
        if !matches!(
            one_core::mapper::x509::subject_key_identifier(&certificate),
            Ok(Some(_))
        ) {
            return untrusted("the MSO status `certificate` has no Subject Key Identifier");
        }
        Self::from_der(der)
    }

    fn from_der(der: &[u8]) -> Result<Self> {
        let certificate = parse(der)?;
        let ski = one_core::mapper::x509::subject_key_identifier(&certificate)
            .ok()
            .flatten()
            .unwrap_or_else(|| ANCHOR_WITHOUT_SKI.to_string());
        tracing::debug!(anchor_ski = %ski, "list trust anchor chosen");
        let pem =
            one_core::mapper::x509::x5c_into_pem_chain(&[STANDARD.encode(der)]).map_err(|err| {
                VCStatusSnafu {
                    details: format!("could not encode the list's trust anchor: {err}"),
                }
                .build()
            })?;
        Ok(Self::Anchor { ski, pem })
    }
}

impl IssuerName {
    fn of(certificate: &X509Certificate<'_>) -> Result<Self> {
        let authority_key_id = one_core::mapper::x509::authority_key_identifier(certificate)
            .map_err(|err| {
                VCStatusSnafu {
                    details: format!("could not read an Authority Key Identifier: {err}"),
                }
                .build()
            })?;
        Ok(Self {
            name: certificate.issuer().as_raw().to_vec(),
            authority_key_id,
        })
    }

    /// Fails unless the top of `pem_chain` is issued under this name and key identifier.
    pub(crate) fn check_top_of(&self, pem_chain: &str) -> Result<()> {
        let chain = chain_ders(Some(pem_chain))?;
        let top = chain.last().ok_or_else(no_issuer_chain)?;
        if &IssuerName::of(&parse(top)?)? == self {
            return Ok(());
        }
        untrusted("the list is not issued under the issuer of the Document Signer chain")
    }
}

/// The held certificate that signed `top`, matched by subject and signature. Of several, it
/// prefers one within its validity, then the latest `notAfter`, then the lowest DER, so the order
/// of `held` does not matter.
fn signer_of<'h>(
    top: &X509Certificate<'_>,
    held: &'h [Vec<u8>],
    now: OffsetDateTime,
) -> Option<&'h [u8]> {
    held.iter()
        .filter_map(|der| {
            let (_, anchor) = x509_parser::parse_x509_certificate(der).ok()?;
            let signed = anchor.subject() == top.issuer()
                && top.verify_signature(Some(anchor.public_key())).is_ok();
            signed.then(|| {
                let not_after = anchor.validity().not_after.to_datetime();
                (within_validity(&anchor, now), not_after, der)
            })
        })
        .max_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)).then_with(|| b.2.cmp(a.2)))
        .map(|(_, _, der)| der.as_slice())
}

/// Whether `now` is within the validity of `certificate`, give or take [VALIDITY_LEEWAY].
fn within_validity(certificate: &X509Certificate<'_>, now: OffsetDateTime) -> bool {
    let validity = certificate.validity();
    now + VALIDITY_LEEWAY >= validity.not_before.to_datetime()
        && now - VALIDITY_LEEWAY <= validity.not_after.to_datetime()
}

/// Every certificate of the PEM `chain`, leaf first. Fails on a block that does not decode.
fn chain_ders(chain: Option<&str>) -> Result<Vec<Vec<u8>>> {
    let chain = chain.ok_or_else(no_issuer_chain)?;
    let ders = x509_parser::pem::Pem::iter_from_buffer(chain.as_bytes())
        .map(|pem| pem.map(|pem| pem.contents))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| {
            VCStatusSnafu {
                details: format!("could not read the issuer certificate chain: {err}"),
            }
            .build()
        })?;
    if ders.is_empty() {
        return Err(no_issuer_chain());
    }
    Ok(ders)
}

fn no_issuer_chain() -> crate::vc::status_formats::Error {
    VCStatusSnafu {
        details: "the credential has no issuer certificate chain to bind its list to",
    }
    .build()
}

fn first_der(pem: &str) -> Option<Vec<u8>> {
    x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes())
        .next()
        .and_then(|pem| pem.ok())
        .map(|pem| pem.contents)
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>> {
    match x509_parser::parse_x509_certificate(der) {
        Ok(([], certificate)) => Ok(certificate),
        Ok(_) => untrusted("a certificate is followed by extra bytes"),
        Err(err) => VCStatusSnafu {
            details: format!("could not parse a certificate: {err}"),
        }
        .fail(),
    }
}

fn untrusted<T>(details: &str) -> Result<T> {
    VCStatusSnafu { details }.fail()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NO_ANCHORS: [&str; 0] = [];

    struct Pki {
        iaca: String,
        other_iaca: String,
        document_signer: String,
        list_signer: String,
        other_list_signer: String,
        external_ca: String,
        expired_ca: String,
    }

    fn ca(common_name: &str, key: &test_fixtures::JWK, not_after: &str) -> String {
        test_fixtures::x509(
            &json!({
                "subject": [["CN", common_name]],
                "not_before": "2025-01-01", "not_after": not_after,
                "ca": true, "key_usages": ["key_cert_sign", "crl_sign"]
            }),
            key,
            None,
        )
    }

    fn leaf(common_name: &str, issuer: (&str, &test_fixtures::JWK)) -> String {
        test_fixtures::x509(
            &json!({
                "subject": [["CN", common_name]],
                "not_before": "2025-01-01", "not_after": "2046-01-01",
                "ca": false, "key_usages": ["digital_signature"],
                "authority_key_identifier": true
            }),
            &test_fixtures::JWK::generate_p256(),
            Some(issuer),
        )
    }

    fn pki() -> Pki {
        let iaca_key = test_fixtures::JWK::generate_p256();
        let iaca = ca("Test IACA", &iaca_key, "2046-01-01");
        let other_key = test_fixtures::JWK::generate_p256();
        let other_iaca = ca("Other IACA", &other_key, "2046-01-01");
        Pki {
            document_signer: leaf("Test Document Signer", (&iaca, &iaca_key)),
            list_signer: leaf("Test List Signer", (&iaca, &iaca_key)),
            other_list_signer: leaf("Other List Signer", (&other_iaca, &other_key)),
            external_ca: ca(
                "Revocation CA",
                &test_fixtures::JWK::generate_p256(),
                "2046-01-01",
            ),
            expired_ca: ca(
                "Expired CA",
                &test_fixtures::JWK::generate_p256(),
                "2025-06-01",
            ),
            iaca,
            other_iaca,
        }
    }

    fn der(pem: &str) -> Vec<u8> {
        first_der(pem).unwrap()
    }

    fn anchor_der(trust: &ListTrust) -> Vec<u8> {
        match trust {
            ListTrust::Anchor { pem, .. } => der(pem),
            other => panic!("expected an anchor, got {other:?}"),
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[test]
    fn without_certificate_the_anchor_is_the_ca_that_signed_the_document_signer() {
        let pki = pki();
        let held = [&pki.other_iaca, &pki.iaca];

        let trust =
            ListTrust::mdoc_anchored(None, Some(&pki.document_signer), &held, true, now()).unwrap();

        assert_eq!(anchor_der(&trust), der(&pki.iaca));
    }

    #[test]
    fn without_certificate_or_a_held_signer_the_list_is_untrusted() {
        let pki = pki();
        let held = [&pki.other_iaca];

        let error = ListTrust::mdoc_anchored(None, Some(&pki.document_signer), &held, true, now())
            .unwrap_err()
            .to_string();

        assert!(error.contains("no trusted anchor signed"), "{error}");
    }

    #[test]
    fn a_pinned_document_signer_is_its_own_list_anchor() {
        let pki = pki();
        let held = [&pki.document_signer];

        let trust =
            ListTrust::mdoc_anchored(None, Some(&pki.document_signer), &held, true, now()).unwrap();

        assert_eq!(anchor_der(&trust), der(&pki.document_signer));
    }

    #[test]
    fn the_mso_certificate_is_the_only_anchor_and_need_not_be_held() {
        let pki = pki();
        let held = [&pki.iaca];
        let certificate = der(&pki.external_ca);

        let trust = ListTrust::mdoc_anchored(
            Some(&certificate),
            Some(&pki.document_signer),
            &held,
            true,
            now(),
        )
        .unwrap();

        assert_eq!(anchor_der(&trust), certificate);
    }

    #[test]
    fn an_unverified_mso_certificate_is_used_only_when_held() {
        let pki = pki();
        let certificate = der(&pki.external_ca);

        let error = ListTrust::mdoc_anchored(
            Some(&certificate),
            Some(&pki.document_signer),
            &[&pki.iaca],
            false,
            now(),
        )
        .unwrap_err()
        .to_string();
        let trust = ListTrust::mdoc_anchored(
            Some(&certificate),
            Some(&pki.document_signer),
            &[&pki.external_ca],
            false,
            now(),
        )
        .unwrap();

        assert!(error.contains("unverified credential"), "{error}");
        assert_eq!(anchor_der(&trust), certificate);
    }

    #[test]
    fn an_mso_certificate_outside_its_validity_is_rejected() {
        let pki = pki();
        let certificate = der(&pki.expired_ca);

        let error = ListTrust::mdoc_anchored(
            Some(&certificate),
            Some(&pki.document_signer),
            &NO_ANCHORS,
            true,
            now(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("validity period"), "{error}");
    }

    #[test]
    fn without_an_issuer_chain_the_list_is_untrusted() {
        let error = ListTrust::mdoc_anchored(None, None, &NO_ANCHORS, true, now())
            .unwrap_err()
            .to_string();

        assert!(error.contains("no issuer certificate chain"), "{error}");
    }

    #[test]
    fn integrity_only_binds_the_list_to_the_document_signer_issuer() {
        let pki = pki();

        let trust =
            ListTrust::mdoc_integrity_only(None, Some(&pki.document_signer), now()).unwrap();
        let ListTrust::SameIssuerAs(issuer) = trust else {
            panic!("expected an issuer binding");
        };

        assert!(issuer.check_top_of(&pki.list_signer).is_ok());
        assert!(issuer.check_top_of(&pki.document_signer).is_ok());
        assert!(issuer.check_top_of(&pki.other_list_signer).is_err());
    }

    #[test]
    fn integrity_only_with_a_certificate_anchors_on_it() {
        let pki = pki();
        let certificate = der(&pki.external_ca);

        let trust =
            ListTrust::mdoc_integrity_only(Some(&certificate), Some(&pki.document_signer), now())
                .unwrap();

        assert_eq!(anchor_der(&trust), certificate);
    }

    fn ca_under(
        common_name: &str,
        key: &test_fixtures::JWK,
        issuer: (&str, &test_fixtures::JWK),
    ) -> String {
        test_fixtures::x509(
            &json!({
                "subject": [["CN", common_name]],
                "not_before": "2025-01-01", "not_after": "2046-01-01",
                "ca": true, "key_usages": ["key_cert_sign", "crl_sign"],
                "authority_key_identifier": true
            }),
            key,
            Some(issuer),
        )
    }

    #[test]
    fn a_pinned_document_signer_anchors_its_lists_when_its_ca_is_in_the_chain() {
        let pki = pki();
        let chain = format!("{}{}", pki.document_signer, pki.iaca);
        let held = [&pki.document_signer];

        let trust = ListTrust::mdoc_anchored(None, Some(&chain), &held, true, now()).unwrap();

        assert_eq!(anchor_der(&trust), der(&pki.document_signer));
    }

    #[test]
    fn the_ca_in_the_chain_anchors_the_lists_when_it_is_held() {
        let pki = pki();
        let chain = format!("{}{}", pki.document_signer, pki.iaca);
        let held = [&pki.iaca, &pki.document_signer];

        let trust = ListTrust::mdoc_anchored(None, Some(&chain), &held, true, now()).unwrap();

        assert_eq!(anchor_der(&trust), der(&pki.iaca));
    }

    #[test]
    fn a_held_intermediate_below_an_unheld_root_anchors_the_lists() {
        let root_key = test_fixtures::JWK::generate_p256();
        let root = ca("Unheld Root", &root_key, "2046-01-01");
        let intermediate_key = test_fixtures::JWK::generate_p256();
        let intermediate = ca_under("Held Intermediate", &intermediate_key, (&root, &root_key));
        let document_signer = leaf("Document Signer", (&intermediate, &intermediate_key));
        let chain = format!("{document_signer}{intermediate}{root}");
        let held = [&intermediate];

        let trust = ListTrust::mdoc_anchored(None, Some(&chain), &held, true, now()).unwrap();

        assert_eq!(anchor_der(&trust), der(&intermediate));
    }

    #[test]
    fn a_held_ca_with_the_same_name_but_another_key_is_not_the_signer() {
        let pki = pki();
        let look_alike = ca(
            "Test IACA",
            &test_fixtures::JWK::generate_p256(),
            "2046-01-01",
        );
        let held = [&look_alike];

        let error = ListTrust::mdoc_anchored(None, Some(&pki.document_signer), &held, true, now())
            .unwrap_err()
            .to_string();

        assert!(error.contains("no trusted anchor signed"), "{error}");
    }

    #[test]
    fn an_mso_certificate_not_yet_valid_is_rejected() {
        let pki = pki();
        let certificate = der(&pki.external_ca);
        let before = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        let error = ListTrust::mdoc_anchored(
            Some(&certificate),
            Some(&pki.document_signer),
            &NO_ANCHORS,
            true,
            before,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("validity period"), "{error}");
    }

    #[test]
    fn integrity_only_anchors_on_a_self_signed_chain_top() {
        let pki = pki();
        let chain = format!("{}{}", pki.document_signer, pki.iaca);

        let trust = ListTrust::mdoc_integrity_only(None, Some(&chain), now()).unwrap();

        assert_eq!(anchor_der(&trust), der(&pki.iaca));
    }

    #[test]
    fn integrity_only_rejects_a_list_whose_top_has_another_authority_key_identifier() {
        let pki = pki();
        let look_alike_key = test_fixtures::JWK::generate_p256();
        let look_alike = ca("Test IACA", &look_alike_key, "2046-01-01");
        let signer = leaf("Look-alike List Signer", (&look_alike, &look_alike_key));

        let trust =
            ListTrust::mdoc_integrity_only(None, Some(&pki.document_signer), now()).unwrap();
        let ListTrust::SameIssuerAs(issuer) = trust else {
            panic!("expected an issuer binding");
        };

        assert!(issuer.check_top_of(&signer).is_err());
    }

    fn at(rfc3339: &str) -> OffsetDateTime {
        OffsetDateTime::parse(rfc3339, &time::format_description::well_known::Rfc3339).unwrap()
    }

    #[test]
    fn an_mso_certificate_without_a_subject_key_identifier_is_rejected() {
        let pki = pki();
        let without_ski = test_fixtures::x509(
            &json!({
                "subject": [["CN", "No Key Identifier"]],
                "not_before": "2025-01-01", "not_after": "2046-01-01"
            }),
            &test_fixtures::JWK::generate_p256(),
            None,
        );
        let certificate = der(&without_ski);
        let parsed = parse(&certificate).unwrap();
        assert!(matches!(
            one_core::mapper::x509::subject_key_identifier(&parsed),
            Ok(None)
        ));

        let error = ListTrust::mdoc_anchored(
            Some(&certificate),
            Some(&pki.document_signer),
            &NO_ANCHORS,
            true,
            now(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("no Subject Key Identifier"), "{error}");
    }

    #[test]
    fn a_held_but_expired_certificate_of_an_unverified_mso_is_rejected() {
        let pki = pki();
        let certificate = der(&pki.expired_ca);

        let error = ListTrust::mdoc_anchored(
            Some(&certificate),
            Some(&pki.document_signer),
            &[&pki.expired_ca],
            false,
            now(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("validity period"), "{error}");
    }

    #[test]
    fn integrity_only_rejects_an_expired_certificate() {
        let pki = pki();
        let certificate = der(&pki.expired_ca);

        let error =
            ListTrust::mdoc_integrity_only(Some(&certificate), Some(&pki.document_signer), now())
                .unwrap_err()
                .to_string();

        assert!(error.contains("validity period"), "{error}");
    }

    #[test]
    fn an_mso_certificate_is_valid_within_the_leeway_and_not_beyond() {
        let pki = pki();
        let certificate = der(&pki.expired_ca);
        let anchored = |now| {
            ListTrust::mdoc_anchored(
                Some(&certificate),
                Some(&pki.document_signer),
                &NO_ANCHORS,
                true,
                now,
            )
        };

        assert!(anchored(at("2025-06-01T00:00:30Z")).is_ok());
        assert!(anchored(at("2025-06-01T00:02:00Z")).is_err());
    }

    #[test]
    fn of_two_held_signers_the_one_within_its_validity_is_chosen_in_any_order() {
        let key = test_fixtures::JWK::generate_p256();
        let expired = ca("Renewed IACA", &key, "2025-06-01");
        let renewed = ca("Renewed IACA", &key, "2046-01-01");
        let document_signer = leaf("Document Signer", (&renewed, &key));

        for held in [[&expired, &renewed], [&renewed, &expired]] {
            let trust =
                ListTrust::mdoc_anchored(None, Some(&document_signer), &held, true, now()).unwrap();

            assert_eq!(anchor_der(&trust), der(&renewed));
        }
    }

    #[test]
    fn a_forged_chain_top_naming_a_held_ca_is_not_the_signer() {
        let pki = pki();
        let forged = ca(
            "Test IACA",
            &test_fixtures::JWK::generate_p256(),
            "2046-01-01",
        );
        let chain = format!("{}{}", pki.document_signer, forged);

        let error = ListTrust::mdoc_anchored(None, Some(&chain), &[&pki.iaca], true, now())
            .unwrap_err()
            .to_string();

        assert!(error.contains("no trusted anchor signed"), "{error}");
    }

    #[test]
    fn integrity_only_does_not_anchor_on_a_self_signed_top_that_is_not_a_ca() {
        let self_signed_leaf = test_fixtures::x509(
            &json!({
                "subject": [["CN", "Self-signed Signer"]],
                "not_before": "2025-01-01", "not_after": "2046-01-01",
                "ca": false, "key_usages": ["digital_signature"]
            }),
            &test_fixtures::JWK::generate_p256(),
            None,
        );

        let trust = ListTrust::mdoc_integrity_only(None, Some(&self_signed_leaf), now()).unwrap();

        assert!(matches!(trust, ListTrust::SameIssuerAs(_)), "{trust:?}");
    }
}
