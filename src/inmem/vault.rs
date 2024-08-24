use async_rwlock::RwLock;
use async_trait::async_trait;
use futures::future;
use std::collections::HashMap;

use crate::inmem::storage::InMemStorage;
use crate::storage::Storage;
use crate::vault::{Error, FindCriteria, Vault};
use crate::vc::{Credential, CredentialMetadata};

pub struct InMemVault {
    storage: InMemStorage<String, Credential>,
    indexed: RwLock<HashMap<String, Vec<String>>>,
}

impl InMemVault {
    pub fn for_store(storage: InMemStorage<String, Credential>) -> Self {
        Self { storage, indexed: RwLock::new(HashMap::new()) }
    }

    pub fn new() -> Self {
        Self { storage: InMemStorage::new(), indexed: RwLock::new(HashMap::new()) }
    }


    async fn update_index(&self, metadata: &CredentialMetadata, storage_id: &str) -> Result<(), Error> {
        let index = format!("{}:{}", metadata.type_, metadata.format);

        let mut vec: Vec<String> = vec![];
        vec.push(storage_id.to_owned());

        if let Some(existing) = self.indexed.read().await.get(&index) {
            vec.extend(existing.to_owned());
        }

        self.indexed.write().await.insert(index, vec);

        Ok(())
    }

    async fn get_indexed(&self, type_: &str, format: &str) -> Vec<String> {
        let index = format!("{}:{}", type_, format);
        let map = self.indexed.read().await;
        let vec = map.get(&index);
        vec.cloned().unwrap_or_else(|| Vec::new())
    }
}

#[async_trait]
impl Vault for InMemVault {
    async fn store_credential(&self, credential: Credential, metadata: &CredentialMetadata) -> Result<String, Error> {
        let storage_id = random_string::generate(5, random_string::charsets::ALPHA);

        let _ = self.storage
            .put(storage_id.clone(), credential.clone())
            .await
            .map_err(|err| Error::Storage(err.to_string()))?;

        self.update_index(metadata, &storage_id).await?;

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
            FindCriteria::ByTypeAndFormat(type_, fmt) => {
                let ids = self.get_indexed(&type_, &fmt).await;
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
