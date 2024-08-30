use crate::vc::formats::HasClaims;
use crate::vc::{Credential, CredentialMetadata};

/// `Metadata` Error.
///
/// Should be used by all `CredentialMetadataProcessor` implementations.
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("format not supported")]
    FormatNotSupported,
    #[error("resolving failed: {0}")]
    Resolving(String),
}

/// `Result` alias for `MetadataProcessor` [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// A common service to generate a [CredentialMetadata] for the [Credential].
///
/// # Implementation
///
/// Default implementation: [DefaultMetadataProcessor].
pub trait CredentialMetadataProcessor {
    /// Resolve a `CredentialMetadata` for `Credential`.
    ///
    /// # Arguments
    ///
    /// * `credential` - a `Credential`.
    ///
    /// # Returns
    ///
    /// A `CredentialMetadata` of the provided `Credential` on success.
    ///
    /// # Errors
    ///
    /// * [Error::FormatNotSupported] - format is not supported by the processor.
    /// * [Error::Resolving] - fails to resolve `Credential`.
    fn resolve_metadata(credential: &Credential) -> Result<CredentialMetadata>;
}

/// A default implementation of [CredentialMetadataProcessor].
///
/// Fills in mandatory `type` and `format` for [CredentialMetadata].
pub struct DefaultMetadataProcessor;

impl DefaultMetadataProcessor {
    fn type_(credential: &Credential) -> Result<String> {
        match credential {
            Credential::LdpVc(w3c_vc) => {
                let type_ = w3c_vc.type_.clone().into_iter().last()
                    .unwrap_or("VerifiableCredential".to_string());
                Ok(type_)
            }
            Credential::SdJwt(jwt) => {
                let claims = jwt.parse_claims()
                    .map_err(|err| Error::Resolving(err.to_string()))?;

                let type_ = claims["vct"].as_str()
                    .ok_or(Error::Resolving("vct not found".to_owned()))?;
                Ok(type_.to_owned())
            }
            _ => Err(Error::FormatNotSupported)?,
        }
    }
}

impl CredentialMetadataProcessor for DefaultMetadataProcessor {
    fn resolve_metadata(credential: &Credential) -> Result<CredentialMetadata> {
        let format = credential.format();
        let type_ = Self::type_(credential)?;

        Ok(CredentialMetadata { type_, format, alg: None, tags: vec![] })
    }
}

