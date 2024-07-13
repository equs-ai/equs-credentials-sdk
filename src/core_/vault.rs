use std::fmt;
use crate::core_::vc;


// Error handling
#[derive(fmt::Debug)]
pub enum VaultError {}

// Basic types definitions
pub struct FindCriteria;

pub trait Vault
{
    fn open(&self, master_secret: &str) -> Result<(), VaultError>;

    fn close(&self) -> Result<(), VaultError>;

    async fn store_credential(&self, credential: vc::Credential) -> Result<String, VaultError>;

    async fn get_credential(&self, id: String) -> Result<vc::Credential, VaultError>;

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<vc::Credential>, VaultError>;
}

pub trait Storage<K, V> {
    async fn put(&self, k: &K, v: &V) -> Result<(), VaultError>;

    async fn get(&self, k: &K) -> Result<Option<V>, VaultError>;
}