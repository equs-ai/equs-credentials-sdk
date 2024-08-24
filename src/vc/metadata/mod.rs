use crate::vc::formats::HasClaims;
use crate::vc::{Credential, CredentialMetadata};

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("format not supported")]
    FormatNotSupported,
    #[error("resolving failed: {0}")]
    Resolving(String),
}

pub type Result<T> = core::result::Result<T, Error>;

pub trait CredentialMetadataProcessor {
    fn resolve_metadata(credential: &Credential) -> Result<CredentialMetadata>;
}

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

