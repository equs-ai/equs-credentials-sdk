use agent_sdk::vault::Vault;
use agent_sdk::vc::{Credential, CredentialMetadata};

use crate::common::{Error, Result};

pub type CredentialEntry = agent_sdk::vault::CredentialEntry;

#[uniffi::remote(Record)]
pub struct CredentialEntry {
    pub credential: Credential,
    pub kid: String,
    pub id: String,
}

#[derive(uniffi::Object)]
pub struct InMemVault(agent_sdk::inmem::vault::InMemVault);

#[uniffi::export()]
impl InMemVault {
    #[uniffi::constructor]
    pub fn new() -> Self {
        InMemVault(agent_sdk::inmem::vault::InMemVault::new())
    }

    pub async fn get_credential(&self, id: String) -> Result<Option<CredentialEntry>> {
        self.0
            .get_credential(&id)
            .await
            .map_err(|err| Error::Vault(format!("{:?}", err)))
    }

    pub async fn store_credential(
        &self,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<String> {
        self.0
            .store_credential(credential, &metadata)
            .await
            .map_err(|err| Error::Vault(format!("{:?}", err)))
    }
}

impl InMemVault {
    pub fn inner(&self) -> agent_sdk::inmem::vault::InMemVault {
        self.0.clone()
    }
}
