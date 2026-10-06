use crate::utils::jwk::from_one_core_public_key_jwk_jsonwebtoken_jwk;
use crate::vc::formats::sd_jwt_vc::SdJwtRsError;
use async_trait::async_trait;
use common_macros::DebugError;
use jsonwebtoken::{DecodingKey, Header};
use one_core::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, EnforceKeyUsage, ParsedCertificate,
    validate_chain_against_trust_anchors,
};
use one_core::provider::key_algorithm::key::KeyHandle;
use one_core::validator::x509::is_dns_name_matching;
use sd_jwt_rs::resolver::KeyResolver;
use snafu::{Location, Snafu};
use std::collections::HashMap;
use tracing::Level;
use tracing::instrument;
use url::Url;
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;

#[derive(DebugError, Snafu)]
pub enum TruststoreError {
    #[snafu(display("Certificate chain is not trusted: {details}"))]
    UntrustedChain {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Issuer identity validation failed: {details}"))]
    IssuerValidation {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Token header does not contain x5c"))]
    X5cHeaderMissing {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("X509 Public Key Info to JWK conversion failed: {details}"))]
    PublicKeyX509JwkConversion {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
}

pub struct Truststore<T: CertificateValidator> {
    cert_validator: T,
    /// PEM of each trusted anchor, keyed by its Subject Key Identifier.
    trusted_roots: HashMap<String, String>,
    enforce_issuer_domain: bool,
}

impl<T: CertificateValidator> Truststore<T> {
    pub fn new(cert_validator: T, trusted_roots: HashMap<String, String>) -> Self {
        Self {
            cert_validator,
            trusted_roots,
            enforce_issuer_domain: false,
        }
    }

    pub fn enforce_issuer_domain(mut self, enabled: bool) -> Self {
        self.enforce_issuer_domain = enabled;
        self
    }

    /// Validates `pem_chain` up to a held anchor and, when issuer-domain binding is enabled, that
    /// `iss` names a `dNSName` SAN of the leaf. Returns the parsed leaf.
    #[instrument(level = Level::TRACE, skip(self, pem_chain), err())]
    pub async fn verify_chain_trust(
        &self,
        pem_chain: &str,
        iss: &str,
    ) -> Result<ParsedCertificate, TruststoreError> {
        let leaf_certificate = validate_chain_against_trust_anchors(
            &self.cert_validator,
            pem_chain,
            &self.trusted_roots,
            || {
                CertificateValidationOptions::signature_and_revocation(Some(vec![
                    EnforceKeyUsage::DigitalSignature,
                ]))
            },
        )
        .await
        .map_err(|e| {
            UntrustedChainSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        if self.enforce_issuer_domain {
            verify_domain_matches_certificate(&issuer_domain(iss)?, &leaf_certificate)?;
        } else {
            tracing::debug!("Issuer domain binding is not enforced; skipping SAN check");
        }

        Ok(leaf_certificate)
    }
}

fn issuer_domain(iss: &str) -> Result<String, TruststoreError> {
    let iss_url = Url::parse(iss).map_err(|e| {
        IssuerValidationSnafu {
            details: format!("iss claim is not a URL: {e}"),
        }
        .build()
    })?;

    iss_url.domain().map(str::to_string).ok_or_else(|| {
        IssuerValidationSnafu {
            details: "iss URL contains no domain name".to_string(),
        }
        .build()
    })
}

fn verify_domain_matches_certificate(
    expected_domain: &str,
    cert: &ParsedCertificate,
) -> Result<(), TruststoreError> {
    let san = cert
        .attributes
        .extensions
        .iter()
        .find(|ext| OID_X509_EXT_SUBJECT_ALT_NAME.to_string().eq(&ext.oid));

    let found_in_san = if let Some(san) = san {
        san.value
            .split("\n")
            .filter_map(|san_entry| {
                san_entry
                    .strip_prefix("DNSName(")
                    .and_then(|entry| entry.strip_suffix(")"))
            })
            .any(|dns| is_dns_name_matching(dns, expected_domain))
    } else {
        false
    };

    if found_in_san {
        Ok(())
    } else {
        Err(IssuerValidationSnafu {
            details: format!("Issuer domain {expected_domain} is not referenced in a SAN entry"),
        }
        .build())
    }
}

impl From<TruststoreError> for SdJwtRsError {
    fn from(e: TruststoreError) -> Self {
        Self::Unspecified(e.to_string())
    }
}

#[async_trait]
impl<T: CertificateValidator> KeyResolver for Truststore<T> {
    #[instrument(level = Level::TRACE, skip(self, header), err())]
    async fn resolve(&self, iss: &str, header: &Header) -> sd_jwt_rs::error::Result<DecodingKey> {
        let chain = header.x5c.clone().ok_or(SdJwtRsError::Unspecified(
            "sd-jwt-vc token contains no x5c header".to_string(),
        ))?;
        let pem_chain =
            one_core::mapper::x509::x5c_into_pem_chain(chain.as_slice()).map_err(|e| {
                SdJwtRsError::Unspecified(format!("Failed to parse x5c as PEM chain: {e}"))
            })?;

        let token_issuer_cert = self.verify_chain_trust(&pem_chain, iss).await?;

        x509_pub_key_to_decoding_key(token_issuer_cert.public_key)
    }
}

fn x509_pub_key_to_decoding_key(kh: KeyHandle) -> Result<DecodingKey, SdJwtRsError> {
    let jwk = kh
        .public_key_as_jwk()
        .map_err(|err| SdJwtRsError::Unspecified(err.to_string()))?;

    let jwk = from_one_core_public_key_jwk_jsonwebtoken_jwk(jwk).ok_or_else(|| {
        SdJwtRsError::Unspecified(
            "Failed to convert one-core JWK public key type to jsonwebtoken".to_string(),
        )
    })?;

    DecodingKey::from_jwk(&jwk).map_err(|e| SdJwtRsError::Unspecified(e.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{anchors, skid_of};
    use crate::utils::x509_truststore::Truststore;
    use jsonwebtoken::{Algorithm, Header};
    use one_core::mapper::x509::pem_chain_into_x5c;
    use one_core::proto::certificate_validator::{
        CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl,
    };
    use rstest::*;
    use sd_jwt_rs::resolver::KeyResolver;
    use sd_jwt_rs::{SDJWTSerializationFormat, SDJWTVerifier};
    use serde_json::json;
    use std::collections::HashMap;

    fn truststore(trusted_roots: HashMap<String, String>) -> Truststore<CertificateValidatorImpl> {
        Truststore::new(CertificateValidatorImpl::default(), trusted_roots)
    }

    #[rstest]
    #[case::issuer_chain(anchors(&[test_root_ca()]), test_issuer_cert(), "https://issuer.example/vc")]
    #[case::web_pki_chain(anchors(&[github_root_ca()]), github_cert_chain(), "https://github.com")]
    #[case::iss_is_not_a_url(anchors(&[test_root_ca()]), test_issuer_cert(), "urn:example:issuer")]
    #[tokio::test]
    async fn trusts_chain_signed_up_to_held_anchor(
        #[case] trusted_roots: HashMap<String, String>,
        #[case] cert_chain: &str,
        #[case] iss: &str,
    ) {
        truststore(trusted_roots)
            .verify_chain_trust(cert_chain, iss)
            .await
            .unwrap();
    }

    #[rstest]
    #[should_panic(expected = "Leaf certificate must not be self-signed")]
    #[case::self_signed_leaf_as_its_own_anchor(
        anchors(&[openid_conformance_test_cert()]),
        openid_conformance_test_cert()
    )]
    #[should_panic(expected = "does not validate against any trusted anchor")]
    #[case::empty_truststore(HashMap::new(), test_issuer_cert())]
    #[should_panic(expected = "does not validate against any trusted anchor")]
    #[case::chain_of_another_anchor(anchors(&[github_root_ca()]), test_issuer_cert())]
    #[should_panic(expected = "Certificate chain is not trusted")]
    #[case::declared_key_id_mapped_to_another_anchor(
        HashMap::from([(skid_of(test_root_ca()), github_root_ca().to_string())]),
        test_issuer_cert()
    )]
    #[tokio::test]
    async fn rejects_chain_not_signed_up_to_held_anchor(
        #[case] trusted_roots: HashMap<String, String>,
        #[case] cert_chain: &str,
    ) {
        truststore(trusted_roots)
            .verify_chain_trust(cert_chain, "https://issuer.example")
            .await
            .unwrap();
    }

    #[rstest]
    #[case::san_match("https://issuer.example/vc", None)]
    #[case::san_mismatch(
        "https://other.example",
        Some("Issuer domain other.example is not referenced in a SAN entry")
    )]
    #[case::iss_without_domain("urn:example:issuer", Some("iss URL contains no domain name"))]
    #[case::iss_not_a_url("issuer", Some("iss claim is not a URL"))]
    #[tokio::test]
    async fn enforced_issuer_domain_must_match_leaf_san(
        #[case] iss: &str,
        #[case] expected_error: Option<&str>,
    ) {
        let result = truststore(anchors(&[test_root_ca()]))
            .enforce_issuer_domain(true)
            .verify_chain_trust(test_issuer_cert(), iss)
            .await;

        match expected_error {
            None => {
                result.unwrap();
            }
            Some(expected) => {
                let error = result.unwrap_err().to_string();
                assert!(error.contains(expected), "unexpected error: {error}");
            }
        }
    }

    #[rstest]
    #[case::apex(github_cert_chain(), "github.com")]
    #[case::www(github_cert_chain(), "www.github.com")]
    #[tokio::test]
    async fn verify_iss_matches_certificate(#[case] pem_chain: &str, #[case] iss: &str) {
        let cert_validator = CertificateValidatorImpl::default();
        let issuer_cert = cert_validator
            .parse_pem_chain(pem_chain, CertificateValidationOptions::no_validation())
            .await;
        super::verify_domain_matches_certificate(iss, &issuer_cert.unwrap()).unwrap();
    }

    #[tokio::test]
    async fn resolves_issuer_key_from_trusted_x5c() {
        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(pem_chain_into_x5c(test_issuer_cert()).unwrap());

        truststore(anchors(&[test_root_ca()]))
            .resolve("https://issuer.example", &header)
            .await
            .unwrap();
    }

    #[rstest]
    #[should_panic(expected = "Leaf certificate must not be self-signed")]
    #[case::self_signed_issuer_cert(anchors(&[openid_conformance_test_cert()]), sd_jwt_vc())]
    #[should_panic(expected = "sd-jwt-vc token contains no x5c header")]
    #[case::no_x5c(anchors(&[openid_conformance_test_cert()]), sd_jwt_vc_no_x5c())]
    #[tokio::test]
    async fn resolve(#[case] trusted_roots: HashMap<String, String>, #[case] sd_jwt: String) {
        let mut sd_jwt_verifier = SDJWTVerifier::new(Box::new(truststore(trusted_roots)));
        sd_jwt_verifier
            .verify_presentation(
                sd_jwt,
                Some("x509_san_dns:verifier-asdk".to_string()),
                Some("psX3cqQAPu3rVVV7Lj0kNqF1Dad6le1B2JRkjwhUN_E".to_string()),
                SDJWTSerializationFormat::Compact,
            )
            .await
            .unwrap();
    }

    /// The test PKI, generated once per process.
    struct Pki {
        /// Self-signed CA; issued `test_issuer_cert`. Valid until 2046.
        test_root_ca: String,
        /// Leaf issued by `test_root_ca`: SAN `DNS:issuer.example`, key usage `digitalSignature`;
        /// certifies the fixture issuer key.
        test_issuer_cert: String,
        /// Self-signed `C=GB, CN=OIDF Test` with the conformance suite's SAN DNS names; certifies
        /// the fixture issuer key.
        openid_conformance_test_cert: String,
        /// Leaf `CN=github.com` (SAN `github.com`, `www.github.com`, EKU `serverAuth`) followed by
        /// its intermediate, `Sectigo Public Server Authentication CA DV E36`, path length 0.
        github_cert_chain: String,
        /// Self-signed `Sectigo Public Server Authentication Root E46`.
        github_root_ca: String,
    }

    fn pki() -> &'static Pki {
        static PKI: std::sync::LazyLock<Pki> = std::sync::LazyLock::new(build_pki);
        &PKI
    }

    fn test_root_ca() -> &'static str {
        &pki().test_root_ca
    }

    fn test_issuer_cert() -> &'static str {
        &pki().test_issuer_cert
    }

    fn openid_conformance_test_cert() -> &'static str {
        &pki().openid_conformance_test_cert
    }

    fn github_cert_chain() -> &'static str {
        &pki().github_cert_chain
    }

    fn github_root_ca() -> &'static str {
        &pki().github_root_ca
    }

    /// `dc+sd-jwt` presentation with key binding, signed by the fixture issuer key under
    /// `openid_conformance_test_cert` in `x5c`.
    fn sd_jwt_vc() -> String {
        presentation(
            Some(pem_chain_into_x5c(openid_conformance_test_cert()).unwrap()),
            1769168000,
            1770377600,
            &[
                r#"["YUmj3wAdlPAmRrwCd1V8Mg","given_name","Jean"]"#,
                r#"["VAaWElABMSaFxhFeZNRNAg","family_name","Dupont"]"#,
                r#"["6LDzfimudpbVXhaKPuxIhA","birthdate","1980-05-23"]"#,
                r#"["VHnhH5BZWXsAT5dCAKEnNA","age_in_years","44"]"#,
            ],
            &[
                "-GC2Ld4PPX9KuskJR3qM8SDLxXXCdYZ7jUt4qurp6Zo",
                "6T-J88j_FUMlsK_UfHwRz98zvo5ddeJ3G_ehIJG8-CM",
                "WDnYXPiyKXWOnP5LQoFipV5GigpONFQGxQMNxImN6r4",
            ],
            "psX3cqQAPu3rVVV7Lj0kNqF1Dad6le1B2JRkjwhUN_E",
        )
    }

    /// `sd_jwt_vc` without `x5c`.
    fn sd_jwt_vc_no_x5c() -> String {
        presentation(
            None,
            1766687147,
            1767896747,
            &[
                r#"["3uoZKGaWC6j5rYicydWUSw","given_name","Jean"]"#,
                r#"["dAAtsEN3jp9FMO0bEcIpJg","family_name","Dupont"]"#,
                r#"["y0HdiMjYqUZXoOxHmkS21Q","birthdate","1980-05-23"]"#,
                r#"["UwTl79ztF4H04ZDNhLJq0g","age_in_years","44"]"#,
            ],
            &[
                "D7eIrYun_6TU_NyVJASe_QYqgWcIcZF-g25grK16Gt0",
                "SwhEJ2JsGC9hVwikyyyixHW5yMGY6aJ4Pdad-3gxr2A",
                "ogBpOV4vkYC0KcsLCsmA3HH66trK5pv1W-MUCqoJFEo",
            ],
            "knmppVOQHcEs69MG3jZAZjneCzbUE0TyBJPPhmRUhA4",
        )
    }

    fn build_pki() -> Pki {
        let keys = test_fixtures::keys();
        let ca_usages = json!(["key_cert_sign", "crl_sign"]);

        let test_root_key = test_fixtures::JWK::generate_p256();
        let test_root_ca = test_fixtures::x509(
            &json!({
                "subject": [["CN", "Test SD-JWT VC Root CA"], ["C", "US"]],
                "not_before": "2026-09-23", "not_after": "2046-09-18",
                "ca": true, "key_usages": ca_usages
            }),
            &test_root_key,
            None,
        );
        let test_issuer_cert = test_fixtures::x509(
            &json!({
                "subject": [["CN", "Test SD-JWT VC Issuer"], ["C", "US"]],
                "sans": ["issuer.example"],
                "not_before": "2026-09-23", "not_after": "2046-09-17",
                "ca": false, "key_usages": ["digital_signature"], "authority_key_identifier": true
            }),
            &keys.issuer,
            Some((&test_root_ca, &test_root_key)),
        );
        let openid_conformance_test_cert = test_fixtures::x509(
            &json!({
                "subject": [["C", "GB"], ["CN", "OIDF Test"]],
                "sans": [
                    "www.heenan.me.uk",
                    "demo.certification.openid.net",
                    "localhost",
                    "localhost.emobix.co.uk",
                    "demo.pid-issuer.bundesdruckerei.de"
                ],
                "not_before": "2024-11-25", "not_after": "2034-11-23",
                "ca": true
            }),
            &keys.issuer,
            None,
        );

        let sectigo = |cn: &str| json!([["C", "GB"], ["O", "Sectigo Limited"], ["CN", cn]]);
        let github_root_key = test_fixtures::JWK::generate_p256();
        let github_root_ca = test_fixtures::x509(
            &json!({
                "subject": sectigo("Sectigo Public Server Authentication Root E46"),
                "not_before": "2026-04-24", "not_after": "2036-04-21",
                "ca": true, "key_usages": ca_usages
            }),
            &github_root_key,
            None,
        );
        let intermediate_key = test_fixtures::JWK::generate_p256();
        let intermediate_cert = test_fixtures::x509(
            &json!({
                "subject": sectigo("Sectigo Public Server Authentication CA DV E36"),
                "not_before": "2026-04-24", "not_after": "2036-04-21",
                "ca": { "path_len": 0 }, "key_usages": ca_usages, "authority_key_identifier": true
            }),
            &intermediate_key,
            Some((&github_root_ca, &github_root_key)),
        );
        let github_leaf = test_fixtures::x509(
            &json!({
                "subject": [["CN", "github.com"]],
                "sans": ["github.com", "www.github.com"],
                "not_before": "2026-04-24", "not_after": "2036-04-21",
                "ca": false, "key_usages": ["digital_signature"],
                "extended_key_usages": ["server_auth"], "authority_key_identifier": true
            }),
            &test_fixtures::JWK::generate_p256(),
            Some((&intermediate_cert, &intermediate_key)),
        );

        Pki {
            test_root_ca,
            test_issuer_cert,
            openid_conformance_test_cert,
            github_cert_chain: format!("{github_leaf}{intermediate_cert}"),
            github_root_ca,
        }
    }

    /// `dc+sd-jwt` presentation of the conformance suite's PID, bound to the fixture holder key;
    /// `undisclosed` holds the recorded digests of the claims it does not disclose.
    fn presentation(
        x5c: Option<Vec<String>>,
        iat: u64,
        exp: u64,
        disclosures: &[&str],
        undisclosed: &[&str],
        nonce: &str,
    ) -> String {
        let keys = test_fixtures::keys();
        let mut header = serde_json::json!({ "typ": "dc+sd-jwt", "alg": "ES256" });
        if let Some(x5c) = x5c {
            header["x5c"] = serde_json::json!(x5c);
        }
        let sd_jwt = test_fixtures::sd_jwt(
            &header,
            &serde_json::json!({
                "_sd": undisclosed,
                "vct": "urn:eudi:pid:1",
                "iss": "https://localhost.emobix.co.uk:9443/test/a/asdk-vci-verifier-test-asdk-598",
                "cnf": { "jwk": keys.holder.to_public() },
                "exp": exp,
                "iat": iat
            }),
            disclosures,
            &keys.issuer,
        );
        test_fixtures::sd_jwt_kb(
            &sd_jwt,
            &serde_json::json!({ "typ": "kb+jwt", "alg": "ES256" }),
            &serde_json::json!({ "aud": "x509_san_dns:verifier-asdk", "iat": iat, "nonce": nonce }),
            &keys.holder,
        )
    }
}
