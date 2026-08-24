use async_trait::async_trait;
use equs_sdk::vault::Vault as EqusSdkVault;
use equs_sdk::vc::{Credential, CredentialMetadata};

use crate::common::{Error, Result};
use crate::vault::{CredentialEntry, Vault, VaultFetchOptions};

#[derive(uniffi::Object, Debug)]
pub struct InMemVault(equs_sdk::inmem::vault::InMemVault);

#[uniffi::export()]
#[async_trait]
impl Vault for InMemVault {
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<String> {
        self.0
            .store_credential(credential, &metadata)
            .await
            .map_err(|err| Error::Vault(format!("{:?}", err)))
    }

    async fn delete_credential(&self, id: String) -> Result<()> {
        self.0
            .delete_credential(&id)
            .await
            .map_err(|err| Error::Vault(format!("{:?}", err)))
    }

    async fn get_credential(&self, id: String) -> Result<Option<CredentialEntry>> {
        self.0
            .get_credential(&id)
            .await
            .map_err(|err| Error::Vault(format!("{:?}", err)))
    }

    async fn get_credentials(
        &self,
        options: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>> {
        let options = options.map(Into::into);

        self.0
            .get_credentials(options)
            .await
            .map_err(|err| Error::Vault(format!("{:?}", err)))
    }

    async fn find_credentials(
        &self,
        fields: Vec<String>,
        options: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>> {
        let options = options.map(Into::into);

        self.0
            .find_credentials(fields, options)
            .await
            .map_err(|err| Error::Vault(format!("{:?}", err)))
    }
}

#[uniffi::export()]
impl InMemVault {
    #[uniffi::constructor]
    fn new() -> Self {
        InMemVault(equs_sdk::inmem::vault::InMemVault::new())
    }
}

impl InMemVault {
    pub fn inner(&self) -> equs_sdk::inmem::vault::InMemVault {
        self.0.clone()
    }
}
