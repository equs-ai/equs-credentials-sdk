use crate::core_::vc;


// Error handling
pub enum VaultError {}

// Basic types definitions
pub struct FindCriteria;

pub trait Vault
{
    fn open(master_secret: String) -> Result<(), VaultError>;

    fn close() -> Result<(), VaultError>;

    async fn store_credential(credential: vc::Credential) -> Result<String, VaultError>;

    async fn get_credential(id: String) -> Result<vc::Credential, VaultError>;

    async fn find_credentials(criteria: FindCriteria) -> Result<Vec<vc::Credential>, VaultError>;
}