use async_trait::async_trait;

use crate::core_::{storage, vc};
use crate::core_::vc::CredentialMetadata;

// Error handling
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    VC(#[from] vc::Error),
    #[error(transparent)]
    Storage(#[from] storage::Error),
}

#[non_exhaustive]
pub enum FindCriteria {
    ByIdAndFormat(String, vc::VCFormat),
    // etc
}

#[async_trait]
pub trait Vault: Send + Sync
{
    fn open(&self, master_secret: &str) -> Result<(), Error>;

    fn close(&self) -> Result<(), Error>;

    async fn store_credential(&mut self, credential: vc::Credential, metadata: &CredentialMetadata) -> Result<String, Error>;

    async fn get_credential(&self, id: &String) -> Result<&vc::Credential, Error>;

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<&vc::Credential>, Error>;
}