use openid4vp::core::dcql::DcqlCredential;
pub use openid4vp::core::dcql::{KeyIdentifier, TrustedAuthority};
use serde::Serialize;

#[cfg(not(target_arch = "wasm32"))]
use crate::vc::trust::issuer::TrustAnchor;

/// Why an anchor contributed no `aki` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AkiSkipReason {
    /// The PEM is not a certificate.
    Unparseable,
    /// A CA without an SKI, or a non-CA certificate without an AKI.
    NoKeyIdentifier,
}

/// An anchor that contributed no `aki` value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedAnchor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    pub reason: AkiSkipReason,
}

/// The `aki` values a verifier can request for a set of anchors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedAuthorityAkis {
    /// Deduplicated and sorted by their base64url form.
    pub values: Vec<KeyIdentifier>,
    pub skipped: Vec<SkippedAnchor>,
}

/// The `aki` values for the issuer anchors in `anchors` (HAIP 1.0 §5): a CA's SKI, or a non-CA
/// certificate's own AKI. Non-issuing anchors are left out; anchors lacking the identifier are
/// listed in [TrustedAuthorityAkis::skipped].
#[cfg(not(target_arch = "wasm32"))]
pub fn derive_trusted_authority_akis(anchors: &[TrustAnchor]) -> TrustedAuthorityAkis {
    let mut derived = TrustedAuthorityAkis::default();
    for anchor in anchors.iter().filter(|anchor| anchor.anchors_issuers()) {
        let skip = |reason| SkippedAnchor {
            source_ref: anchor.source_ref.clone(),
            reason,
        };
        let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(anchor.pem.as_bytes()) else {
            derived.skipped.push(skip(AkiSkipReason::Unparseable));
            continue;
        };
        let Ok(certificate) = pem.parse_x509() else {
            derived.skipped.push(skip(AkiSkipReason::Unparseable));
            continue;
        };
        let key_identifier = if certificate.is_ca() {
            subject_key_identifier(&certificate)
        } else {
            authority_key_identifier(&certificate)
        };
        match key_identifier.and_then(|bytes| KeyIdentifier::from_bytes(&bytes).ok()) {
            Some(value) => derived.values.push(value),
            None => derived.skipped.push(skip(AkiSkipReason::NoKeyIdentifier)),
        }
    }
    derived
        .values
        .sort_by(|a, b| a.as_base64url().cmp(b.as_base64url()));
    derived.values.dedup();
    derived
}

/// The Authority Key Identifiers of every certificate in `chain_pem` (leaf first).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn chain_authority_key_identifiers(chain_pem: &str) -> Vec<Vec<u8>> {
    x509_parser::pem::Pem::iter_from_buffer(chain_pem.as_bytes())
        .filter_map(Result::ok)
        .filter_map(|pem| {
            pem.parse_x509()
                .ok()
                .and_then(|certificate| authority_key_identifier(&certificate))
        })
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn subject_key_identifier(
    certificate: &x509_parser::certificate::X509Certificate,
) -> Option<Vec<u8>> {
    use x509_parser::extensions::ParsedExtension;
    certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(key_identifier) => {
                Some(key_identifier.0.to_vec())
            }
            _ => None,
        })
}

#[cfg(not(target_arch = "wasm32"))]
fn authority_key_identifier(
    certificate: &x509_parser::certificate::X509Certificate,
) -> Option<Vec<u8>> {
    use x509_parser::extensions::ParsedExtension;
    certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(authority) => authority
                .key_identifier
                .as_ref()
                .map(|key_identifier| key_identifier.0.to_vec()),
            _ => None,
        })
}

/// The `aki` values a credential for `query` must match; `None` when not checked.
pub(crate) fn required_akis(query: &DcqlCredential) -> Option<Vec<&KeyIdentifier>> {
    let authorities = query.trusted_authorities()?;
    let mut akis = vec![];
    for authority in authorities.iter() {
        match authority {
            TrustedAuthority::Aki(values) => akis.extend(values.iter()),
            _ => return None,
        }
    }
    (!akis.is_empty()).then_some(akis)
}

/// Whether the issuer chain's AKIs (`None` without a chain) match one of `required`.
pub(crate) fn matches_required_akis(
    required: &[&KeyIdentifier],
    chain_akis: Option<&[Vec<u8>]>,
) -> bool {
    chain_akis.is_some_and(|chain_akis| {
        chain_akis.iter().any(|aki| {
            required
                .iter()
                .any(|value| value.as_bytes() == aki.as_slice())
        })
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use serde_json::json;

    use super::*;

    fn anchor(pem: &str, source_ref: &str) -> TrustAnchor {
        TrustAnchor {
            source_ref: Some(source_ref.to_string()),
            ..TrustAnchor::new(pem)
        }
    }

    /// A CA and a non-CA certificate (with an AKI) it issued.
    fn ca_and_leaf() -> (String, String) {
        let ca_key = test_fixtures::JWK::generate_p256();
        let ca = test_fixtures::x509(
            &json!({ "subject": [["CN", "Derivation CA"]], "ca": true, "key_usages": ["key_cert_sign"] }),
            &ca_key,
            None,
        );
        let leaf = test_fixtures::x509(
            &json!({
                "subject": [["CN", "Listed Signer"]], "sans": ["signer.example"],
                "key_usages": ["digital_signature"], "authority_key_identifier": true
            }),
            &test_fixtures::keys().issuer,
            Some((&ca, &ca_key)),
        );
        (ca, leaf)
    }

    fn ski_of(pem: &str) -> Vec<u8> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        subject_key_identifier(&pem.parse_x509().unwrap()).unwrap()
    }

    #[test]
    fn a_ca_anchor_gives_its_ski_and_a_listed_certificate_its_aki() {
        let (ca, leaf) = ca_and_leaf();

        let derived = derive_trusted_authority_akis(&[anchor(&ca, "ca"), anchor(&leaf, "leaf")]);

        // the leaf's AKI is the CA's SKI: one value, deduplicated
        assert_eq!(derived.values.len(), 1, "{derived:?}");
        assert_eq!(derived.values[0].as_bytes(), ski_of(&ca));
        assert!(derived.skipped.is_empty());
    }

    #[test]
    fn anchors_without_a_key_identifier_or_not_a_certificate_are_skipped() {
        let ca_key = test_fixtures::JWK::generate_p256();
        // a SAN, so rcgen writes an extensions block
        let leaf_without_aki = test_fixtures::x509(
            &json!({ "subject": [["CN", "No AKI"]], "sans": ["no-aki.example"] }),
            &ca_key,
            None,
        );

        let derived = derive_trusted_authority_akis(&[
            anchor(&leaf_without_aki, "no-aki"),
            anchor("-----BEGIN CERTIFICATE-----", "garbage"),
        ]);

        assert!(derived.values.is_empty());
        assert_eq!(
            derived.skipped,
            [
                SkippedAnchor {
                    source_ref: Some("no-aki".to_string()),
                    reason: AkiSkipReason::NoKeyIdentifier,
                },
                SkippedAnchor {
                    source_ref: Some("garbage".to_string()),
                    reason: AkiSkipReason::Unparseable,
                },
            ]
        );
    }

    #[test]
    fn a_revocation_service_anchor_gives_no_value() {
        let (ca, _) = ca_and_leaf();
        let revocation = TrustAnchor {
            service_type: Some("http://uri.etsi.org/19602/SvcType/PID/Revocation".to_string()),
            ..anchor(&ca, "revocation")
        };

        let derived = derive_trusted_authority_akis(&[revocation]);

        assert!(derived.values.is_empty());
        assert!(derived.skipped.is_empty());
    }

    #[test]
    fn values_are_sorted_and_deduplicated() {
        let (first, _) = ca_and_leaf();
        let (second, _) = ca_and_leaf();

        let derived = derive_trusted_authority_akis(&[
            anchor(&second, "2"),
            anchor(&first, "1"),
            anchor(&second, "2 again"),
        ]);

        assert_eq!(derived.values.len(), 2);
        assert!(derived.values[0].as_base64url() < derived.values[1].as_base64url());
    }

    fn query(trusted_authorities: serde_json::Value) -> DcqlCredential {
        serde_json::from_value(json!({
            "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] },
            "trusted_authorities": trusted_authorities
        }))
        .unwrap()
    }

    #[test]
    fn only_aki_only_queries_are_checked() {
        let aki_only = query(json!([{ "type": "aki", "values": ["AQID"] }]));
        let with_etsi_tl = query(json!([
            { "type": "aki", "values": ["AQID"] },
            { "type": "etsi_tl", "values": ["https://tl.example.com"] }
        ]));
        let etsi_tl_only =
            query(json!([{ "type": "etsi_tl", "values": ["https://tl.example.com"] }]));

        assert_eq!(required_akis(&aki_only).unwrap().len(), 1);
        assert!(required_akis(&with_etsi_tl).is_none());
        assert!(required_akis(&etsi_tl_only).is_none());
    }

    #[test]
    fn a_chain_matches_when_any_certificate_names_a_requested_authority() {
        let (ca, leaf) = ca_and_leaf();
        let requested = KeyIdentifier::from_bytes(&ski_of(&ca)).unwrap();
        let other = KeyIdentifier::from_bytes(&[9, 9, 9]).unwrap();
        let chain_akis = chain_authority_key_identifiers(&leaf);

        assert!(matches_required_akis(
            &[&other, &requested],
            Some(&chain_akis)
        ));
        assert!(!matches_required_akis(&[&other], Some(&chain_akis)));
        // a DID issuer has no chain
        assert!(!matches_required_akis(&[&requested], None));
    }
}
