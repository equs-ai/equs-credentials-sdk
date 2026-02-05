use crate::utils::jwk::from_one_core_public_key_jwk_jsonwebtoken_jwk;
use crate::vc::formats::sd_jwt_vc::SdJwtRsError;
use async_trait::async_trait;
use common_macros::DebugError;
use jsonwebtoken::{DecodingKey, Header};
use one_core::mapper::x509::last_cert_authority_key_identifier_from_pem_chain;
use one_core::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use one_core::provider::key_algorithm::key::KeyHandle;
use one_core::validator::x509::is_dns_name_matching;
use sd_jwt_rs::resolver::KeyResolver;
use snafu::{Location, ResultExt, Snafu};
use std::collections::HashSet;
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
    trusted_root_skids: HashSet<String>,
}

impl<T: CertificateValidator> Truststore<T> {
    pub fn new(cert_validator: T, trusted_root_skids: HashSet<String>) -> Self {
        Self {
            cert_validator,
            trusted_root_skids,
        }
    }

    #[instrument(level = Level::TRACE, skip(self, pem_chain), err())]
    pub async fn verify_chain_trust(
        &self,
        pem_chain: &str,
        expected_domain: &str,
    ) -> Result<ParsedCertificate, TruststoreError> {
        let leaf_certificate = self
            .cert_validator
            .parse_pem_chain(
                pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
            .map_err(|e| {
                CertificateChainSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        self.verify_root_ca_is_trusted(pem_chain)?;
        verify_domain_matches_certificate(expected_domain, &leaf_certificate)?;

        Ok(leaf_certificate)
    }

    fn verify_root_ca_is_trusted(&self, pem_chain: &str) -> Result<(), TruststoreError> {
        let last_cert_akid =
            last_cert_authority_key_identifier_from_pem_chain(pem_chain).context(OneCoreSnafu)?;
        if self.trusted_root_skids.contains(&last_cert_akid) {
            Ok(())
        } else {
            Err(UntrustedRootSnafu {
                skid: last_cert_akid,
            }
            .build())
        }
    }
}

fn verify_domain_matches_certificate(
    expected_domain: &str,
    cert: &ParsedCertificate,
) -> Result<(), TruststoreError> {
    if let Some(cert_scn) = &cert.subject_common_name
        && is_dns_name_matching(cert_scn, expected_domain)
    {
        return Ok(());
    }

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
            details: format!("Issuer domain {expected_domain} is not referenced in SCN or SAN"),
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
    use std::collections::HashSet;
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
    #[case::positive_self_signed_server_cert(
        trusted_skids_with_root_ca(OPENID_CONFORMANCE_TEST_CERT),
        OPENID_CONFORMANCE_TEST_CERT,
        "localhost.emobix.co.uk"
    )]
    #[should_panic(expected = "Untrusted root CA SKID")]
    #[case::empty_truststore(HashSet::new(), GITHUB_CERT_CHAIN, "github.com")]
    #[should_panic(expected = "Untrusted root CA SKID")]
    #[case::untrusted_ca(
        trusted_skids_with_root_ca(OPENID_CONFORMANCE_TEST_CERT),
        GITHUB_CERT_CHAIN,
        "github.com"
    )]
    #[tokio::test]
    async fn resolve_issuer_key_and_validate_trust(
        #[case] trusted_skids: HashSet<String>,
        #[case] cert_chain: &str,
        #[case] expected_domain: &str,
    ) {
        let truststore = Truststore::new(CertificateValidatorImpl::default(), trusted_skids);
        truststore
            .verify_chain_trust(cert_chain, expected_domain)
            .await
            .unwrap();
    }

    fn trusted_skids_with_root_ca(ca_cert: &str) -> HashSet<String> {
        let cert = Pem::iter_from_buffer(ca_cert.as_bytes())
            .next()
            .unwrap()
            .unwrap();

        let mut trusted_root_skids = HashSet::new();

        let certificate = cert.parse_x509().unwrap();

        trusted_root_skids.insert(subject_key_identifier(&certificate).unwrap().unwrap());

        trusted_root_skids
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
    #[case(trusted_skids_with_root_ca(OPENID_CONFORMANCE_TEST_CERT), SD_JWT_VC)]
    #[should_panic(expected = "Untrusted root CA SKID")]
    #[case::negative(HashSet::new(), SD_JWT_VC)]
    #[should_panic(expected = "sd-jwt-vc token contains no x5c header")]
    #[case::negative(
        trusted_skids_with_root_ca(OPENID_CONFORMANCE_TEST_CERT),
        SD_JWT_VC_NO_X5C
    )]
    #[tokio::test]
    async fn resolve(#[case] trusted_skids: HashSet<String>, #[case] sd_jwt: &str) {
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

    const GITHUB_CERT_CHAIN: &str = "-----BEGIN CERTIFICATE-----
MIID7DCCA5OgAwIBAgIQAnZWif7lL4XEyKR2UOhLvjAKBggqhkjOPQQDAjBgMQsw
CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5T
ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgRFYgRTM2MB4X
DTI2MDEwNjAwMDAwMFoXDTI2MDQwNTIzNTk1OVowFTETMBEGA1UEAxMKZ2l0aHVi
LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGeldVCWGAdfVTEkqFJBU7ed
OJiBN7F37N5SlBfm2u/VS3kskbtUh0XHIpNsJrctqyln8TGzO/ioN/RpQj6TS8Kj
ggJ4MIICdDAfBgNVHSMEGDAWgBQXmagEwW/kLXCoChA9A9PpGrgmYzAdBgNVHQ4E
FgQUWLkzCBHzL3v9j+RHkWoiuDbJCJMwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB
/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwSQYDVR0gBEIwQDA0BgsrBgEEAbIx
AQICBzAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZn
gQwBAgEwgYQGCCsGAQUFBwEBBHgwdjBPBggrBgEFBQcwAoZDaHR0cDovL2NydC5z
ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljU2VydmVyQXV0aGVudGljYXRpb25DQURW
RTM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wggEE
BgorBgEEAdZ5AgQCBIH1BIHyAPAAdgAOV5S8866pPjMbLJkHs/eQ35vCPXEyJd0h
qSWsYcVOIQAAAZuQnYruAAAEAwBHMEUCIBZ9yM14lKxW6dlATCQ4roIirc3X4+Sx
ggcQsseC0/yVAiEAlx5VEA/+902bqEcvo278U/wsnB+bNPQ/fmuyQC92RlAAdgDR
bqmlaAd+ZjWgPzel3bwDpTxBEhTUiBj16TGzI8uVBAAAAZuQnYugAAAEAwBHMEUC
IQD3lHdwCs6lPEXkrQuoDLn6FpQDS6wKt2+bVZsuh/TiEwIgHrZtusMmPR+a0O8q
NiK9ISsCp8OMLOhldo6hcSODtQAwJQYDVR0RBB4wHIIKZ2l0aHViLmNvbYIOd3d3
LmdpdGh1Yi5jb20wCgYIKoZIzj0EAwIDRwAwRAIgf3cLQS5ngZPU3Rxlw5i8s5OI
GGUwxyITvVTXYh6axsgCIFn9/zCvXlM8jz5HXnuCHrZs7levpWzvFhhMH2Qr6ACw
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDXzCCAuagAwIBAgIQNuBZ7YiN1Xrt1XC2cn+b2jAKBggqhkjOPQQDAzBfMQsw
CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1T
ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwHhcN
MjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBgMQswCQYDVQQGEwJHQjEYMBYG
A1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIFB1YmxpYyBT
ZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgRFYgRTM2MFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEaKGnbAUnBYljHDmn/yUhxe3TLxKYuyzc9VXoSaCEV5F73Fhfa/Si
/RMsmwTFW3R9s7J6JpYZFmu4do3vk/Vgl6OCAYEwggF9MB8GA1UdIwQYMBaAFNEi
2kxZ8UtfJjiqndbu6w3D+6lhMB0GA1UdDgQWBBQXmagEwW/kLXCoChA9A9PpGrgm
YzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEC
ATBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
Z29QdWJsaWNTZXJ2ZXJBdXRoZW50aWNhdGlvblJvb3RFNDYuY3JsMIGEBggrBgEF
BQcBAQR4MHYwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2Vj
dGlnb1B1YmxpY1NlcnZlckF1dGhlbnRpY2F0aW9uUm9vdEU0Ni5wN2MwIwYIKwYB
BQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMAoGCCqGSM49BAMDA2cAMGQC
MFsKnBQDh64l+v+aUYWjDCJKQMxHUUGmcwAYDIjJ9pbRYItMCIx5xu0oUb6sIfTX
qQIwPddcsDE4KdeLu1hJdpHgdLvsHAK3vygyLGujMU9xBJCDackRT93VHEE0gppg
NqdV
-----END CERTIFICATE-----";

    const GITHUB_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----
MIICOjCCAcGgAwIBAgIQQvLM2htpN0RfFf51KBC49DAKBggqhkjOPQQDAzBfMQsw
CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1T
ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwHhcN
MjEwMzIyMDAwMDAwWhcNNDYwMzIxMjM1OTU5WjBfMQswCQYDVQQGEwJHQjEYMBYG
A1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1YmxpYyBT
ZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAR2+pmpbiDt+dd34wc7qNs9Xzjoq1WmVk/WSOrsfy2qw7LFeeyZYX8QeccC
WvkEN/U0NSt3zn8gj1KjAIns1aeibVvjS5KToID1AZTc8GgHHs3u/iVStSBDHBv+
6xnOQ6OjQjBAMB0GA1UdDgQWBBTRItpMWfFLXyY4qp3W7usNw/upYTAOBgNVHQ8B
Af8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjAn7qRa
qCG76UeXlImldCBteU/IvZNeWBj7LRoAasm4PdCkT0RHlAFWovgzJQxC36oCMB3q
4S6ILuH5px0CMk7yn2xVdOOurvulGu7t0vzCAxHrRVxgED1cf5kDW21USAGKcw==
-----END CERTIFICATE-----";

    const SD_JWT_VC: &str = "eyJ4NWMiOlsiTUlJQ0hqQ0NBY09nQXdJQkFnSVVaWDlCUzVDRE9KUlcydDFGSzFVRE10L1F3TUV3Q2dZSUtvWkl6ajBFQXdJd0lURUxNQWtHQTFVRUJoTUNSMEl4RWpBUUJnTlZCQU1NQ1U5SlJFWWdWR1Z6ZERBZUZ3MHlOREV4TWpVd09ETTJNRFJhRncwek5ERXhNak13T0RNMk1EUmFNQ0V4Q3pBSkJnTlZCQVlUQWtkQ01SSXdFQVlEVlFRRERBbFBTVVJHSUZSbGMzUXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBVFQvZExzZDUxTExCckdWNlIyM282dnltUnhIWGVGQm9JOHlxMzF5NWtGVjJWVjBnaTl4NVp6RUZpcThETWlBSHVjTEFDRm5keEx0Wm9yQ2hhOXp6blFvNEhZTUlIVk1CMEdBMVVkRGdRV0JCUzVjYmRnQWVNQmk1d3hwYnB3SVNHaFNoQVdFVEFmQmdOVkhTTUVHREFXZ0JTNWNiZGdBZU1CaTV3eHBicHdJU0doU2hBV0VUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01JR0JCZ05WSFJFRWVqQjRnaEIzZDNjdWFHVmxibUZ1TG0xbExuVnJnaDFrWlcxdkxtTmxjblJwWm1sallYUnBiMjR1YjNCbGJtbGtMbTVsZElJSmJHOWpZV3hvYjNOMGdoWnNiMk5oYkdodmMzUXVaVzF2WW1sNExtTnZMblZyZ2lKa1pXMXZMbkJwWkMxcGMzTjFaWEl1WW5WdVpHVnpaSEoxWTJ0bGNtVnBMbVJsTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDSVFDUGJuTHhDSStXUjF2aE9XK0E4S3puQVd2MU1KbytZRWIxTUk0NU5LVy9WUUloQUx6c3FveDhWdUJSd04yZGw1TGtwbnhQNG9IOXA2SDBBT1ptS1ArWTduWFMiXSwidHlwIjoiZGMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJfc2QiOlsiLUdDMkxkNFBQWDlLdXNrSlIzcU04U0RMeFhYQ2RZWjdqVXQ0cXVycDZabyIsIjZULUo4OGpfRlVNbHNLX1VmSHdSejk4enZvNWRkZUozR19laElKRzgtQ00iLCI4WFdheXdEM1NQSzVxWlY2ZnNjcUhwUTNOa1ZXZEQ5QzlxTVdaUzRZeDZzIiwiV0RuWVhQaXlLWFdPblA1TFFvRmlwVjVHaWdwT05GUUd4UU1OeEltTjZyNCIsImM0Vlo5RkVlQ1VfaU9OWnFWZ1QwNFVlZkQxQUZHMDg0RHhqZjAxSTRhM0kiLCJtb3pHZWFzcmJuYmdIbUxzU2MyZDBZV2xadlVtanFfQlphUFR0YzNLZnM0IiwicGswUkdJVkhYSFRUaVJuRkRYbElyd1JBcFNDZmxDaHBKTElocGVVMVh4QSJdLCJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSIsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LmVtb2JpeC5jby51azo5NDQzL3Rlc3QvYS9hc2RrLXZjaS12ZXJpZmllci10ZXN0LWFzZGstNTk4IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjZUbUhSYVFIQWpwbXVUYzVLakVmOXhPOXk2MXZsLW1oLXdrbkFnenMzaFEiLCJ5IjoiYXhwUlhqak9nM1lzclZ2UzNUcEZyZGhBT1liR0F6YUZscTk3SHFCQ1IzcyJ9fSwiZXhwIjoxNzcwMzc3NjAwLCJpYXQiOjE3NjkxNjgwMDB9.sdoSEYncmx84v3TOj_ffSZvQ_pjQ5y1z2l5Gt9KIMUs7CL_lO81TMMwNGV-KY0n8slFKZLxZZgIiisZWx-gy6g~WyJZVW1qM3dBZGxQQW1ScndDZDFWOE1nIiwiZ2l2ZW5fbmFtZSIsIkplYW4iXQ~WyJWQWFXRWxBQk1TYUZ4aEZlWk5STkFnIiwiZmFtaWx5X25hbWUiLCJEdXBvbnQiXQ~WyI2TER6ZmltdWRwYlZYaGFLUHV4SWhBIiwiYmlydGhkYXRlIiwiMTk4MC0wNS0yMyJd~WyJWSG5oSDVCWldYc0FUNWRDQUtFbk5BIiwiYWdlX2luX3llYXJzIiwiNDQiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiQk0tVVduSmZpdFVSLTRzaWZUbThIMkNNdW5aTWc4UXA0QUxVOVlMRDEtTSIsImF1ZCI6Ing1MDlfc2FuX2Ruczp2ZXJpZmllci1hc2RrIiwiaWF0IjoxNzY5MTY4MDAwLCJub25jZSI6InBzWDNjcVFBUHUzclZWVjdMajBrTnFGMURhZDZsZTFCMkpSa2p3aFVOX0UifQ.TPh8fnO5vG_sxi-stt2o3XJqfUF07fIi-4JQzv_xf1-QpYgspbE5LbEhsVWuTiykHWK-RvcBc4-bS9lg7OGLpA";
    const SD_JWT_VC_NO_X5C: &str = "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiLTBSVllzOWh3TDVLS3lUcE9xYVE2Y0M5UkJESFVtcFhmN3RmRjRtNGVWRSIsIkQ3ZUlyWXVuXzZUVV9OeVZKQVNlX1FZcWdXY0ljWkYtZzI1Z3JLMTZHdDAiLCJTd2hFSjJKc0dDOWhWd2lreXl5aXhIVzV5TUdZNmFKNFBkYWQtM2d4cjJBIiwiVGk2Znc4M2VrbE8xczhsTllPQ1RXdUhVUzB3OXgwUEk2MDNEV0xjWEtPTSIsIldmUUhQOVVJb1ZzTVhUUUFNeklOSlpTSEE5T1Y2VXowTHJFd0U1OEl2TUUiLCJqWmw5MVllT242YnJSelZiZWdsRUt1S3NMX3hOSVhDT2FobHpHaWFIQml3Iiwib2dCcE9WNHZrWUMwS2NzTENzbUEzSEg2NnRySzVwdjFXLU1VQ3FvSkZFbyJdLCJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSIsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LmVtb2JpeC5jby51azo5NDQzL3Rlc3QvYS9hc2RrLXZjaS12ZXJpZmllci10ZXN0LWFzZGstNTk4IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImJWakRPZHc2YlRzdHBrRXJYZlNYR2RyQnVGempNX1VMOU1tZzJPRXpUVFUiLCJ5IjoiNGNURm55SzBkSzFHbmRyc0NFUi00aHMzeTFERGloQW1Pek80T3B4c1djayJ9fSwiZXhwIjoxNzY3ODk2NzQ3LCJpYXQiOjE3NjY2ODcxNDd9.cSYGUI29Ba4nVfCb769_n7n3jchww0qYlvmsJqg3lPXiZtj3pBQUguct3XDzFoI1QHAiaiacEhY5GIB2IFR98w~WyIzdW9aS0dhV0M2ajVyWWljeWRXVVN3IiwiZ2l2ZW5fbmFtZSIsIkplYW4iXQ~WyJkQUF0c0VOM2pwOUZNTzBiRWNJcEpnIiwiZmFtaWx5X25hbWUiLCJEdXBvbnQiXQ~WyJ5MEhkaU1qWXFVWlhvT3hIbWtTMjFRIiwiYmlydGhkYXRlIiwiMTk4MC0wNS0yMyJd~WyJVd1RsNzl6dEY0SDA0WkROaExKcTBnIiwiYWdlX2luX3llYXJzIiwiNDQiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiYjhjeURvT19lV2c3WTNhdkxEQ3pCYkwyS29OSkMwRzIyczlqelRMR01JMCIsImF1ZCI6Ing1MDlfc2FuX2Ruczp2ZXJpZmllci1hc2RrIiwiaWF0IjoxNzY2Njg3MTQ3LCJub25jZSI6ImtubXBwVk9RSGNFczY5TUczalpBWmpuZUN6YlVFMFR5QkpQUGhtUlVoQTQifQ.VkU3S_8FQNyTLCYNMumH2GR_QbjGhYOMi9dlIDPZmpJU1aGshanBf0tRmTGe8-aIeWWoN-hGCmAgYjw4QQ8OSg";
}
