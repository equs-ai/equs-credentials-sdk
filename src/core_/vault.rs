use std::fmt;

use crate::core_::vc;

// Error handling
#[derive(fmt::Debug)]
pub enum Error {}

// Basic types definitions
pub struct FindCriteria;

pub trait Vault
{
    fn open(&self, master_secret: &str) -> Result<(), Error>;

    fn close(&self) -> Result<(), Error>;

    async fn store_credential(&mut self, credential: vc::Credential) -> Result<String, Error>;

    async fn get_credential(&self, id: &String) -> Result<&vc::Credential, Error>;

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<vc::Credential>, Error>;
}