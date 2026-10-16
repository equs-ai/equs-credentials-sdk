use crate::did::DIDURLBuf;
use crate::vc::oid4vci::IssuerUrl;
use std::str::FromStr;

/// Issuer Identifier specified in Issued Credential.
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialIssuerIdentifier {
    /// Credential Issuer Identifier as specified in
    /// [OID4VCI specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-identifie).
    OID4VCI(IssuerUrl),
    /// Issuer Identifier in DID format.
    DID(DIDURLBuf),
    /// An unknown Issuer Identifier format.
    Other(String),
}

impl<T> From<T> for CredentialIssuerIdentifier
where
    T: AsRef<str>,
{
    fn from(value: T) -> Self {
        let issuer_id = value.as_ref();
        if let Ok(did) = DIDURLBuf::from_str(issuer_id) {
            CredentialIssuerIdentifier::DID(did)
        } else if issuer_id.starts_with("https")
            && let Ok(url) = IssuerUrl::new(issuer_id.to_string())
        {
            CredentialIssuerIdentifier::OID4VCI(url)
        } else {
            CredentialIssuerIdentifier::Other(issuer_id.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::did("did:example:123/test-oid4vci-issuer", CredentialIssuerIdentifier::DID(DIDURLBuf::from_str(given).unwrap()))]
    #[case::oid4vci("https://example/test-oid4vci-issuer",
        CredentialIssuerIdentifier::OID4VCI(IssuerUrl::new("https://example/test-oid4vci-issuer".to_string()).unwrap()))]
    #[case::oid4vci_with_port("https://example:8088/test-oid4vci-issuer",
        CredentialIssuerIdentifier::OID4VCI(IssuerUrl::new("https://example:8088/test-oid4vci-issuer".to_string()).unwrap()))]
    #[case::other("d0916841-56aa-4ced-8ee6-3f89e3d7f890",
        CredentialIssuerIdentifier::Other("d0916841-56aa-4ced-8ee6-3f89e3d7f890".to_string()))]
    fn from_str(#[case] given: &str, #[case] expected: CredentialIssuerIdentifier) {
        let actual = CredentialIssuerIdentifier::from(given);
        assert_eq!(expected, actual);
    }
}
