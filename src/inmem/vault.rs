use std::collections::HashMap;

use async_trait::async_trait;
use futures::future;

use crate::inmem::storage::InMemStorage;
use crate::storage::Storage;
use crate::vault::{Error, FindCriteria, Vault};
use crate::vc;
use crate::vc::{Credential, CredentialMetadata};

pub struct InMemVault {
    storage: InMemStorage<String, Credential>,
    indexed: HashMap<String, Vec<String>>,
}

impl InMemVault {
    pub fn for_store(storage: InMemStorage<String, Credential>) -> Self {
        Self { storage, indexed: HashMap::new() }
    }

    pub fn new() -> Self {
        Self { storage: InMemStorage::new(), indexed: HashMap::new() }
    }


    fn update_index(&mut self, metadata: &CredentialMetadata, storage_id: &str) -> Result<(), Error> {
        let index = format!("{}:{}", metadata.id, metadata.format);

        if !self.indexed.contains_key(&index) {
            self.indexed.insert(index.clone(), vec![]);
        }

        self.indexed.get_mut(&index).unwrap().push(storage_id.to_owned());

        Ok(())
    }

    fn get_indexed(&self, id: &str, format: vc::VCFormat) -> Vec<String> {
        let index = format!("{}:{}", id, format);
        let vec = self.indexed.get(&index);
        if vec.is_none() { return Vec::new(); }
        vec.unwrap().to_owned()
    }
}

#[async_trait]
impl Vault for InMemVault {
    async fn store_credential(&mut self, credential: Credential, metadata: &CredentialMetadata) -> Result<String, Error> {
        let storage_id = random_string::generate(5, random_string::charsets::ALPHA);

        let _ = self.storage
            .put(storage_id.clone(), credential.clone())
            .await
            .map_err(|err| Error::Storage(err.to_string()))?;
        self.update_index(metadata, &storage_id)?;

        Ok(storage_id)
    }

    async fn get_credential(&self, id: &str) -> Result<Credential, Error> {
        let cred = self.storage
            .get(&id.to_string())
            .await
            .map_err(|err| Error::Storage(err.to_string()))?;

        Ok(cred.clone())
    }

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<Credential>, Error> {
        let creds = match criteria {
            FindCriteria::ByIdAndFormat(id, fmt) => {
                let ids = self.get_indexed(&id, fmt);
                let creds = future::try_join_all(ids.iter().map(|id| self.get_credential(id)))
                    .await?;
                creds
            }
        };

        Ok(creds)
    }
}

#[cfg(test)]
mod tests {
    use crate::inmem::storage::InMemStorage;
    use crate::inmem::vault::InMemVault;
    use crate::vault::test_util::test_vault;

    #[tokio::test]
    async fn e2e() {
        let storage = InMemStorage::new();
        let vault = InMemVault::for_store(storage);
        test_vault(vault).await;
    }
}
