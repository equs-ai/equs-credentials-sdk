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
    use crate::utils::x509_truststore::Truststore;
    use jsonwebtoken::{Algorithm, Header};
    use one_core::mapper::x509::{pem_chain_into_x5c, subject_key_identifier};
    use one_core::proto::certificate_validator::{
        CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl,
    };
    use rstest::*;
    use sd_jwt_rs::resolver::KeyResolver;
    use sd_jwt_rs::{SDJWTSerializationFormat, SDJWTVerifier};
    use std::collections::HashMap;
    use x509_parser::prelude::Pem;

    fn anchors(ca_certs: &[&str]) -> HashMap<String, String> {
        ca_certs
            .iter()
            .map(|ca_cert| (skid_of(ca_cert), ca_cert.to_string()))
            .collect()
    }

    fn skid_of(cert_pem: &str) -> String {
        let pem = Pem::iter_from_buffer(cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        subject_key_identifier(&pem.parse_x509().unwrap())
            .unwrap()
            .unwrap()
    }

    fn truststore(trusted_roots: HashMap<String, String>) -> Truststore<CertificateValidatorImpl> {
        Truststore::new(CertificateValidatorImpl::default(), trusted_roots)
    }

    #[rstest]
    #[case::issuer_chain(anchors(&[TEST_ROOT_CA]), TEST_ISSUER_CERT, "https://issuer.example/vc")]
    #[case::web_pki_chain(anchors(&[GITHUB_ROOT_CA]), GITHUB_CERT_CHAIN, "https://github.com")]
    #[case::iss_is_not_a_url(anchors(&[TEST_ROOT_CA]), TEST_ISSUER_CERT, "urn:example:issuer")]
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
        anchors(&[OPENID_CONFORMANCE_TEST_CERT]),
        OPENID_CONFORMANCE_TEST_CERT
    )]
    #[should_panic(expected = "does not validate against any trusted anchor")]
    #[case::empty_truststore(HashMap::new(), TEST_ISSUER_CERT)]
    #[should_panic(expected = "does not validate against any trusted anchor")]
    #[case::chain_of_another_anchor(anchors(&[GITHUB_ROOT_CA]), TEST_ISSUER_CERT)]
    #[should_panic(expected = "Certificate chain is not trusted")]
    #[case::declared_key_id_mapped_to_another_anchor(
        HashMap::from([(skid_of(TEST_ROOT_CA), GITHUB_ROOT_CA.to_string())]),
        TEST_ISSUER_CERT
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
        let result = truststore(anchors(&[TEST_ROOT_CA]))
            .enforce_issuer_domain(true)
            .verify_chain_trust(TEST_ISSUER_CERT, iss)
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
    #[case::apex(GITHUB_CERT_CHAIN, "github.com")]
    #[case::www(GITHUB_CERT_CHAIN, "www.github.com")]
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
        header.x5c = Some(pem_chain_into_x5c(TEST_ISSUER_CERT).unwrap());

        truststore(anchors(&[TEST_ROOT_CA]))
            .resolve("https://issuer.example", &header)
            .await
            .unwrap();
    }

    #[rstest]
    #[should_panic(expected = "Leaf certificate must not be self-signed")]
    #[case::self_signed_issuer_cert(anchors(&[OPENID_CONFORMANCE_TEST_CERT]), SD_JWT_VC)]
    #[should_panic(expected = "sd-jwt-vc token contains no x5c header")]
    #[case::no_x5c(anchors(&[OPENID_CONFORMANCE_TEST_CERT]), SD_JWT_VC_NO_X5C)]
    #[tokio::test]
    async fn resolve(#[case] trusted_roots: HashMap<String, String>, #[case] sd_jwt: &str) {
        let mut sd_jwt_verifier = SDJWTVerifier::new(Box::new(truststore(trusted_roots)));
        sd_jwt_verifier
            .verify_presentation(
                sd_jwt.to_string(),
                Some("x509_san_dns:verifier-asdk".to_string()),
                Some("psX3cqQAPu3rVVV7Lj0kNqF1Dad6le1B2JRkjwhUN_E".to_string()),
                SDJWTSerializationFormat::Compact,
            )
            .await
            .unwrap();
    }

    /// Self-signed CA; issued `TEST_ISSUER_CERT`. Valid until 2046.
    const TEST_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBwTCCAWegAwIBAgIUWxwFnkWKOBRX/9BDUaurh6Pn8WwwCgYIKoZIzj0EAwIw
LjEfMB0GA1UEAwwWVGVzdCBTRC1KV1QgVkMgUm9vdCBDQTELMAkGA1UEBhMCVVMw
HhcNMjYwOTIzMDgyNTMwWhcNNDYwOTE4MDgyNTMwWjAuMR8wHQYDVQQDDBZUZXN0
IFNELUpXVCBWQyBSb290IENBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABN7T/1mYtFrbISvrZY43cdyvzgmlNx/ubD89upRX2FD8SS2DvQXx
3gkV3cDmwluiit3f0vW+Ooiuh9oO4PprxbWjYzBhMB8GA1UdIwQYMBaAFI6JJsYa
EPEoOyEJMpuEqugJ39OZMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG
MB0GA1UdDgQWBBSOiSbGGhDxKDshCTKbhKroCd/TmTAKBggqhkjOPQQDAgNIADBF
AiBfGAO7kMRy/cpxrkK6uxZ5+w/Z33rVU2+RKprML+vQXgIhAM0b9fgtY1JoQZ8D
4navNI23qfHsMbLeqBWae0Lt/3h6
-----END CERTIFICATE-----";
    /// Leaf issued by `TEST_ROOT_CA`: SAN `DNS:issuer.example`, key usage `digitalSignature`.
    const TEST_ISSUER_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIB2TCCAX6gAwIBAgIUBB6zIXz4fM1yXKy5aEt4Lwz6O3MwCgYIKoZIzj0EAwIw
LjEfMB0GA1UEAwwWVGVzdCBTRC1KV1QgVkMgUm9vdCBDQTELMAkGA1UEBhMCVVMw
HhcNMjYwOTIzMDgyNTMwWhcNNDYwOTE3MDgyNTMwWjAtMR4wHAYDVQQDDBVUZXN0
IFNELUpXVCBWQyBJc3N1ZXIxCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEy4RWg4SAqjcqUxkDhE30DobP5nv3yuPwb0cwuu6ZTH0EgAbPEPZl
BMWl70UqkU7fWrg3d2ccKCJdSoFnPzV0J6N7MHkwDAYDVR0TAQH/BAIwADAOBgNV
HQ8BAf8EBAMCB4AwGQYDVR0RBBIwEIIOaXNzdWVyLmV4YW1wbGUwHQYDVR0OBBYE
FNiEzQrF1w31Xf2VmE40+LiaOvMeMB8GA1UdIwQYMBaAFI6JJsYaEPEoOyEJMpuE
qugJ39OZMAoGCCqGSM49BAMCA0kAMEYCIQCjyZhd33EaM5xBg74Xs/wbmA7kEpNP
yWVTOGH0aFhhpQIhALuMdY1vn5GsjESEDd4YONR9+blXRyReOAeSBSCLlmuU
-----END CERTIFICATE-----";
    const OPENID_CONFORMANCE_TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIICHjCCAcOgAwIBAgIUZX9BS5CDOJRW2t1FK1UDMt/QwMEwCgYIKoZIzj0EAwIw
ITELMAkGA1UEBhMCR0IxEjAQBgNVBAMMCU9JREYgVGVzdDAeFw0yNDExMjUwODM2
MDRaFw0zNDExMjMwODM2MDRaMCExCzAJBgNVBAYTAkdCMRIwEAYDVQQDDAlPSURG
IFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT/dLsd51LLBrGV6R23o6v
ymRxHXeFBoI8yq31y5kFV2VV0gi9x5ZzEFiq8DMiAHucLACFndxLtZorCha9zznQ
o4HYMIHVMB0GA1UdDgQWBBS5cbdgAeMBi5wxpbpwISGhShAWETAfBgNVHSMEGDAW
gBS5cbdgAeMBi5wxpbpwISGhShAWETAPBgNVHRMBAf8EBTADAQH/MIGBBgNVHREE
ejB4ghB3d3cuaGVlbmFuLm1lLnVrgh1kZW1vLmNlcnRpZmljYXRpb24ub3Blbmlk
Lm5ldIIJbG9jYWxob3N0ghZsb2NhbGhvc3QuZW1vYml4LmNvLnVrgiJkZW1vLnBp
ZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlMAoGCCqGSM49BAMCA0kAMEYCIQCP
bnLxCI+WR1vhOW+A8KznAWv1MJo+YEb1MI45NKW/VQIhALzsqox8VuBRwN2dl5Lk
pnxP4oH9p6H0AOZmKP+Y7nXS
-----END CERTIFICATE-----";

    // Generated 2026-04-24 with 10-year validity using self-signed test CA chain.
    // Leaf: CN=github.com, SAN=github.com,www.github.com — expires 2036-04-21
    // Intermediate: Sectigo Public Server Authentication CA DV E36 (test) — expires 2036-04-21
    const GITHUB_CERT_CHAIN: &str = "-----BEGIN CERTIFICATE-----
MIICFTCCAbugAwIBAgIUHfOdbWcllxGFOJj8RWIX1Pi+IKUwCgYIKoZIzj0EAwIw
YDELMAkGA1UEBhMCR0IxGDAWBgNVBAoMD1NlY3RpZ28gTGltaXRlZDE3MDUGA1UE
AwwuU2VjdGlnbyBQdWJsaWMgU2VydmVyIEF1dGhlbnRpY2F0aW9uIENBIERWIEUz
NjAeFw0yNjA0MjQxMDQyNDJaFw0zNjA0MjExMDQyNDJaMBUxEzARBgNVBAMMCmdp
dGh1Yi5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATVF6PYsWLGV1fQBjWG
cQUQNGBMha1A8xZ2DhUkLvCiBIIibh9cLck5upGK+Na+A1DKN2bZ0/G8ItUm8f6g
nouJo4GdMIGaMB0GA1UdDgQWBBR8kdc7/lXAcnXu3dixoOcPDc8hgjAfBgNVHSME
GDAWgBTzduBYLtYjHL6uvhC/rhzRFdyZGzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB
/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAlBgNVHREEHjAcggpnaXRodWIu
Y29tgg53d3cuZ2l0aHViLmNvbTAKBggqhkjOPQQDAgNIADBFAiEAq7FwJx1GWWil
Ygzw03CxWDbsT9GoOPbQCsPrdttedo8CIA9seorBGqlTsCIMkewEB17U+W01LI3E
L78UNnwPjC8j
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICJzCCAc2gAwIBAgIUPI1Ojrum4YkCyr4bvc0aDebsGtcwCgYIKoZIzj0EAwIw
XzELMAkGA1UEBhMCR0IxGDAWBgNVBAoMD1NlY3RpZ28gTGltaXRlZDE2MDQGA1UE
AwwtU2VjdGlnbyBQdWJsaWMgU2VydmVyIEF1dGhlbnRpY2F0aW9uIFJvb3QgRTQ2
MB4XDTI2MDQyNDEwNDI0MloXDTM2MDQyMTEwNDI0MlowYDELMAkGA1UEBhMCR0Ix
GDAWBgNVBAoMD1NlY3RpZ28gTGltaXRlZDE3MDUGA1UEAwwuU2VjdGlnbyBQdWJs
aWMgU2VydmVyIEF1dGhlbnRpY2F0aW9uIENBIERWIEUzNjBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABOSx389xLO48MV/EVCzmC8am9BnAOYAEG44UxJbLGff16Wlw
NNG7g0YoNvc/NN0HTCMPl9/9MjzslvdvCBsXi/mjZjBkMBIGA1UdEwEB/wQIMAYB
Af8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTzduBYLtYjHL6uvhC/rhzR
FdyZGzAfBgNVHSMEGDAWgBQ7TK85CnvdPtuxs4jnqlKkh6SjAzAKBggqhkjOPQQD
AgNIADBFAiAhx3iZXHIgGnH8ymo1OgMlw2M0V06+vvTEejOmlHGKowIhAPbP+nWX
zsTo5UAK3d5xiYe7zySUjS/LePwwP+Wxq/54
-----END CERTIFICATE-----";

    // Generated 2026-04-24 with 10-year validity — Sectigo Public Server Authentication Root E46 (test)
    // Expires 2036-04-21
    const GITHUB_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----
MIICJDCCAcmgAwIBAgIUBlNqqk9MoHxoE2qO6grp9r7vVZcwCgYIKoZIzj0EAwIw
XzELMAkGA1UEBhMCR0IxGDAWBgNVBAoMD1NlY3RpZ28gTGltaXRlZDE2MDQGA1UE
AwwtU2VjdGlnbyBQdWJsaWMgU2VydmVyIEF1dGhlbnRpY2F0aW9uIFJvb3QgRTQ2
MB4XDTI2MDQyNDEwNDI0MloXDTM2MDQyMTEwNDI0MlowXzELMAkGA1UEBhMCR0Ix
GDAWBgNVBAoMD1NlY3RpZ28gTGltaXRlZDE2MDQGA1UEAwwtU2VjdGlnbyBQdWJs
aWMgU2VydmVyIEF1dGhlbnRpY2F0aW9uIFJvb3QgRTQ2MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEb+Mh53Q0leh1DUFVKMMcK5KAg2X5LRh8QP9E4wtXaSxHsOvM
eHD7kEwg9RzM9tFWAA24NYtkW4x8dNUxL1Elv6NjMGEwHwYDVR0jBBgwFoAUO0yv
OQp73T7bsbOI56pSpIekowMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFDtMrzkKe90+27GziOeqUqSHpKMDMAoGCCqGSM49BAMCA0kA
MEYCIQDte3ZMvXS6W3rbpNIOQzMbmhdpRUBgs8+ZbiB03MRrFQIhAMctAisCkF0M
sPeg62mHhsTg9l5PSRUrvmvYac/4Fz6k
-----END CERTIFICATE-----";

    const SD_JWT_VC: &str = "eyJ4NWMiOlsiTUlJQ0hqQ0NBY09nQXdJQkFnSVVaWDlCUzVDRE9KUlcydDFGSzFVRE10L1F3TUV3Q2dZSUtvWkl6ajBFQXdJd0lURUxNQWtHQTFVRUJoTUNSMEl4RWpBUUJnTlZCQU1NQ1U5SlJFWWdWR1Z6ZERBZUZ3MHlOREV4TWpVd09ETTJNRFJhRncwek5ERXhNak13T0RNMk1EUmFNQ0V4Q3pBSkJnTlZCQVlUQWtkQ01SSXdFQVlEVlFRRERBbFBTVVJHSUZSbGMzUXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBVFQvZExzZDUxTExCckdWNlIyM282dnltUnhIWGVGQm9JOHlxMzF5NWtGVjJWVjBnaTl4NVp6RUZpcThETWlBSHVjTEFDRm5keEx0Wm9yQ2hhOXp6blFvNEhZTUlIVk1CMEdBMVVkRGdRV0JCUzVjYmRnQWVNQmk1d3hwYnB3SVNHaFNoQVdFVEFmQmdOVkhTTUVHREFXZ0JTNWNiZGdBZU1CaTV3eHBicHdJU0doU2hBV0VUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01JR0JCZ05WSFJFRWVqQjRnaEIzZDNjdWFHVmxibUZ1TG0xbExuVnJnaDFrWlcxdkxtTmxjblJwWm1sallYUnBiMjR1YjNCbGJtbGtMbTVsZElJSmJHOWpZV3hvYjNOMGdoWnNiMk5oYkdodmMzUXVaVzF2WW1sNExtTnZMblZyZ2lKa1pXMXZMbkJwWkMxcGMzTjFaWEl1WW5WdVpHVnpaSEoxWTJ0bGNtVnBMbVJsTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDSVFDUGJuTHhDSStXUjF2aE9XK0E4S3puQVd2MU1KbytZRWIxTUk0NU5LVy9WUUloQUx6c3FveDhWdUJSd04yZGw1TGtwbnhQNG9IOXA2SDBBT1ptS1ArWTduWFMiXSwidHlwIjoiZGMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJfc2QiOlsiLUdDMkxkNFBQWDlLdXNrSlIzcU04U0RMeFhYQ2RZWjdqVXQ0cXVycDZabyIsIjZULUo4OGpfRlVNbHNLX1VmSHdSejk4enZvNWRkZUozR19laElKRzgtQ00iLCI4WFdheXdEM1NQSzVxWlY2ZnNjcUhwUTNOa1ZXZEQ5QzlxTVdaUzRZeDZzIiwiV0RuWVhQaXlLWFdPblA1TFFvRmlwVjVHaWdwT05GUUd4UU1OeEltTjZyNCIsImM0Vlo5RkVlQ1VfaU9OWnFWZ1QwNFVlZkQxQUZHMDg0RHhqZjAxSTRhM0kiLCJtb3pHZWFzcmJuYmdIbUxzU2MyZDBZV2xadlVtanFfQlphUFR0YzNLZnM0IiwicGswUkdJVkhYSFRUaVJuRkRYbElyd1JBcFNDZmxDaHBKTElocGVVMVh4QSJdLCJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSIsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LmVtb2JpeC5jby51azo5NDQzL3Rlc3QvYS9hc2RrLXZjaS12ZXJpZmllci10ZXN0LWFzZGstNTk4IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjZUbUhSYVFIQWpwbXVUYzVLakVmOXhPOXk2MXZsLW1oLXdrbkFnenMzaFEiLCJ5IjoiYXhwUlhqak9nM1lzclZ2UzNUcEZyZGhBT1liR0F6YUZscTk3SHFCQ1IzcyJ9fSwiZXhwIjoxNzcwMzc3NjAwLCJpYXQiOjE3NjkxNjgwMDB9.sdoSEYncmx84v3TOj_ffSZvQ_pjQ5y1z2l5Gt9KIMUs7CL_lO81TMMwNGV-KY0n8slFKZLxZZgIiisZWx-gy6g~WyJZVW1qM3dBZGxQQW1ScndDZDFWOE1nIiwiZ2l2ZW5fbmFtZSIsIkplYW4iXQ~WyJWQWFXRWxBQk1TYUZ4aEZlWk5STkFnIiwiZmFtaWx5X25hbWUiLCJEdXBvbnQiXQ~WyI2TER6ZmltdWRwYlZYaGFLUHV4SWhBIiwiYmlydGhkYXRlIiwiMTk4MC0wNS0yMyJd~WyJWSG5oSDVCWldYc0FUNWRDQUtFbk5BIiwiYWdlX2luX3llYXJzIiwiNDQiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiQk0tVVduSmZpdFVSLTRzaWZUbThIMkNNdW5aTWc4UXA0QUxVOVlMRDEtTSIsImF1ZCI6Ing1MDlfc2FuX2Ruczp2ZXJpZmllci1hc2RrIiwiaWF0IjoxNzY5MTY4MDAwLCJub25jZSI6InBzWDNjcVFBUHUzclZWVjdMajBrTnFGMURhZDZsZTFCMkpSa2p3aFVOX0UifQ.TPh8fnO5vG_sxi-stt2o3XJqfUF07fIi-4JQzv_xf1-QpYgspbE5LbEhsVWuTiykHWK-RvcBc4-bS9lg7OGLpA";
    const SD_JWT_VC_NO_X5C: &str = "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiLTBSVllzOWh3TDVLS3lUcE9xYVE2Y0M5UkJESFVtcFhmN3RmRjRtNGVWRSIsIkQ3ZUlyWXVuXzZUVV9OeVZKQVNlX1FZcWdXY0ljWkYtZzI1Z3JLMTZHdDAiLCJTd2hFSjJKc0dDOWhWd2lreXl5aXhIVzV5TUdZNmFKNFBkYWQtM2d4cjJBIiwiVGk2Znc4M2VrbE8xczhsTllPQ1RXdUhVUzB3OXgwUEk2MDNEV0xjWEtPTSIsIldmUUhQOVVJb1ZzTVhUUUFNeklOSlpTSEE5T1Y2VXowTHJFd0U1OEl2TUUiLCJqWmw5MVllT242YnJSelZiZWdsRUt1S3NMX3hOSVhDT2FobHpHaWFIQml3Iiwib2dCcE9WNHZrWUMwS2NzTENzbUEzSEg2NnRySzVwdjFXLU1VQ3FvSkZFbyJdLCJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSIsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LmVtb2JpeC5jby51azo5NDQzL3Rlc3QvYS9hc2RrLXZjaS12ZXJpZmllci10ZXN0LWFzZGstNTk4IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImJWakRPZHc2YlRzdHBrRXJYZlNYR2RyQnVGempNX1VMOU1tZzJPRXpUVFUiLCJ5IjoiNGNURm55SzBkSzFHbmRyc0NFUi00aHMzeTFERGloQW1Pek80T3B4c1djayJ9fSwiZXhwIjoxNzY3ODk2NzQ3LCJpYXQiOjE3NjY2ODcxNDd9.cSYGUI29Ba4nVfCb769_n7n3jchww0qYlvmsJqg3lPXiZtj3pBQUguct3XDzFoI1QHAiaiacEhY5GIB2IFR98w~WyIzdW9aS0dhV0M2ajVyWWljeWRXVVN3IiwiZ2l2ZW5fbmFtZSIsIkplYW4iXQ~WyJkQUF0c0VOM2pwOUZNTzBiRWNJcEpnIiwiZmFtaWx5X25hbWUiLCJEdXBvbnQiXQ~WyJ5MEhkaU1qWXFVWlhvT3hIbWtTMjFRIiwiYmlydGhkYXRlIiwiMTk4MC0wNS0yMyJd~WyJVd1RsNzl6dEY0SDA0WkROaExKcTBnIiwiYWdlX2luX3llYXJzIiwiNDQiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiYjhjeURvT19lV2c3WTNhdkxEQ3pCYkwyS29OSkMwRzIyczlqelRMR01JMCIsImF1ZCI6Ing1MDlfc2FuX2Ruczp2ZXJpZmllci1hc2RrIiwiaWF0IjoxNzY2Njg3MTQ3LCJub25jZSI6ImtubXBwVk9RSGNFczY5TUczalpBWmpuZUN6YlVFMFR5QkpQUGhtUlVoQTQifQ.VkU3S_8FQNyTLCYNMumH2GR_QbjGhYOMi9dlIDPZmpJU1aGshanBf0tRmTGe8-aIeWWoN-hGCmAgYjw4QQ8OSg";
}
