use crate::utils::jwk::from_one_core_public_key_jwk_jsonwebtoken_jwk;
use crate::vc::formats::sd_jwt_vc::SdJwtRsError;
use async_trait::async_trait;
use common_macros::DebugError;
use jsonwebtoken::{DecodingKey, Header};
use one_core::mapper::x509::last_cert_authority_key_identifier_from_pem_chain;
use one_core::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator, ParsedCertificate,
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
    #[snafu(display("Untrusted root CA SKID: {skid}"))]
    UntrustedRoot {
        skid: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Failed to handle certificate chain: {details}"))]
    CertificateChain {
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
    #[snafu(display("One-core error: {source}"))]
    OneCore {
        source: anyhow::Error,
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

    #[instrument(level = Level::TRACE, skip(self, pem_chain), err())]
    pub async fn verify_chain_trust(
        &self,
        pem_chain: &str,
        expected_domain: &str,
    ) -> Result<ParsedCertificate, TruststoreError> {
        let leaf_certificate = self.verify_chain_against_trusted_anchor(pem_chain).await?;

        if let Err(error) = verify_domain_matches_certificate(expected_domain, &leaf_certificate)
            && self.enforce_issuer_domain
        {
            return Err(error);
        }

        Ok(leaf_certificate)
    }

    /// Validates `pem_chain` up to and including a trusted anchor.
    async fn verify_chain_against_trusted_anchor(
        &self,
        pem_chain: &str,
    ) -> Result<ParsedCertificate, TruststoreError> {
        let declared_akid = last_cert_authority_key_identifier_from_pem_chain(pem_chain)
            .ok()
            .filter(|akid| self.trusted_roots.contains_key(akid));

        let candidates: Vec<(&String, &String)> = match &declared_akid {
            Some(akid) => self.trusted_roots.get_key_value(akid).into_iter().collect(),
            None => self.trusted_roots.iter().collect(),
        };

        let mut last_error: Option<String> = None;

        for (skid, anchor_pem) in candidates {
            match self
                .cert_validator
                .validate_chain_against_ca_chain(
                    pem_chain,
                    anchor_pem,
                    CertificateValidationOptions::signature_and_revocation(None),
                    CertSelection::Leaf,
                )
                .await
            {
                Ok(leaf_certificate) => return Ok(leaf_certificate),
                Err(e) => {
                    tracing::debug!(%skid, error = %e, "Chain did not validate against this anchor");
                    last_error = Some(e.to_string());
                }
            }
        }

        Err(UntrustedRootSnafu {
            skid: declared_akid.unwrap_or_else(|| {
                last_error.unwrap_or_else(|| "no trusted anchor validated the chain".to_string())
            }),
        }
        .build())
    }
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
        let iss_url = Url::parse(iss).map_err(|e| {
            SdJwtRsError::Unspecified(format!("sd-jwt-vc token iss claim is not an url: {e}"))
        })?;
        let iss_domain = iss_url.domain().ok_or(SdJwtRsError::Unspecified(format!(
            "sd-jwt-vc token issuer url contains no domain name: {iss_url}"
        )))?;

        let chain = header.x5c.clone().ok_or(SdJwtRsError::Unspecified(
            "sd-jwt-vc token contains no x5c header".to_string(),
        ))?;
        let pem_chain =
            one_core::mapper::x509::x5c_into_pem_chain(chain.as_slice()).map_err(|e| {
                SdJwtRsError::Unspecified("Failed to parse x5c as PEM chain".to_string())
            })?;

        let token_issuer_cert = self.verify_chain_trust(&pem_chain, iss_domain).await?;

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
    use one_core::mapper::x509::subject_key_identifier;
    use one_core::proto::certificate_validator::{
        CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl,
    };
    use rstest::*;
    use sd_jwt_rs::{SDJWTSerializationFormat, SDJWTVerifier};
    use std::collections::HashMap;
    use x509_parser::prelude::Pem;

    #[rstest]
    #[case::positive_domain_in_scn(
        trusted_skids_with_root_ca(GITHUB_ROOT_CA),
        GITHUB_CERT_CHAIN,
        "github.com"
    )]
    #[case::positive_domain_in_san(
        trusted_skids_with_root_ca(GITHUB_ROOT_CA),
        GITHUB_CERT_CHAIN,
        "www.github.com"
    )]
    #[should_panic(expected = "Untrusted root CA SKID")]
    #[case::self_signed_cert_as_its_own_anchor(
        trusted_skids_with_root_ca(OPENID_CONFORMANCE_TEST_CERT),
        OPENID_CONFORMANCE_TEST_CERT,
        "localhost.emobix.co.uk"
    )]
    #[should_panic(expected = "Untrusted root CA SKID")]
    #[case::empty_truststore(HashMap::new(), GITHUB_CERT_CHAIN, "github.com")]
    #[should_panic(expected = "Untrusted root CA SKID")]
    #[case::untrusted_ca(
        trusted_skids_with_root_ca(OPENID_CONFORMANCE_TEST_CERT),
        GITHUB_CERT_CHAIN,
        "github.com"
    )]
    #[tokio::test]
    async fn resolve_issuer_key_and_validate_trust(
        #[case] trusted_skids: HashMap<String, String>,
        #[case] cert_chain: &str,
        #[case] expected_domain: &str,
    ) {
        let truststore = Truststore::new(CertificateValidatorImpl::default(), trusted_skids);
        truststore
            .verify_chain_trust(cert_chain, expected_domain)
            .await
            .unwrap();
    }

    fn trusted_skids_with_root_ca(ca_cert: &str) -> HashMap<String, String> {
        let cert = Pem::iter_from_buffer(ca_cert.as_bytes())
            .next()
            .unwrap()
            .unwrap();

        let certificate = cert.parse_x509().unwrap();
        let skid = subject_key_identifier(&certificate).unwrap().unwrap();

        HashMap::from([(skid, ca_cert.to_string())])
    }

    #[tokio::test]
    async fn rejects_chain_whose_declared_akid_matches_an_anchor_it_was_not_signed_by() {
        let github_root = Pem::iter_from_buffer(GITHUB_ROOT_CA.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let github_skid = subject_key_identifier(&github_root.parse_x509().unwrap())
            .unwrap()
            .unwrap();

        let mismatched_anchor =
            HashMap::from([(github_skid, OPENID_CONFORMANCE_TEST_CERT.to_string())]);

        let truststore = Truststore::new(CertificateValidatorImpl::default(), mismatched_anchor);

        let result = truststore
            .verify_chain_trust(GITHUB_CERT_CHAIN, "github.com")
            .await;

        assert!(
            result.is_err(),
            "a chain must not be trusted merely for declaring a trusted anchor's key identifier"
        );
    }

    #[rstest]
    #[case::scn(GITHUB_CERT_CHAIN, "github.com")]
    #[case::san(GITHUB_CERT_CHAIN, "www.github.com")]
    #[tokio::test]
    async fn verify_iss_matches_certificate(#[case] pem_chain: &str, #[case] iss: &str) {
        let cert_validator = CertificateValidatorImpl::default();
        let issuer_cert = cert_validator
            .parse_pem_chain(pem_chain, CertificateValidationOptions::no_validation())
            .await;
        super::verify_domain_matches_certificate(iss, &issuer_cert.unwrap()).unwrap();
    }

    #[rstest]
    //todo It is positive test but it does not work due to cred exp. Should be updated manually by new created certificate as existing jwt came from conformance tests
    #[should_panic(expected = "Cannot decode jwt: ExpiredSignature")]
    #[case::positive(trusted_skids_with_root_ca(OPENID_CONFORMANCE_TEST_CERT), SD_JWT_VC)]
    #[should_panic(expected = "Untrusted root CA SKID")]
    #[case::negative(HashMap::new(), SD_JWT_VC)]
    #[should_panic(expected = "sd-jwt-vc token contains no x5c header")]
    #[case::negative(
        trusted_skids_with_root_ca(OPENID_CONFORMANCE_TEST_CERT),
        SD_JWT_VC_NO_X5C
    )]
    #[tokio::test]
    async fn resolve(#[case] trusted_skids: HashMap<String, String>, #[case] sd_jwt: &str) {
        let truststore = Truststore::new(CertificateValidatorImpl::default(), trusted_skids);
        let mut sd_jwt_verifier = SDJWTVerifier::new(Box::new(truststore));
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
