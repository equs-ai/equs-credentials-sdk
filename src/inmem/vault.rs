use crate::inmem::storage::InMemStorage;
use crate::storage::Storage;
use crate::vault::{CredentialEntry, Error, FindCriteria, StoringSnafu, Vault};
use crate::vc::{Credential, CredentialMetadata};
use async_rwlock::RwLock;
use async_trait::async_trait;
use futures::future;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{instrument, Level};

#[derive(Debug, Clone)]
pub struct InMemVault {
    storage: Arc<InMemStorage<String, CredentialEntry>>,
    indexed: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl InMemVault {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(InMemStorage::new()),
            indexed: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn update_index(
        &self,
        metadata: &CredentialMetadata,
        storage_id: &str,
    ) -> Result<(), Error> {
        let index = format!("{}:{}", metadata.type_, metadata.format);

        let mut vec: Vec<String> = vec![];
        vec.push(storage_id.to_owned());

        if let Some(existing) = self.indexed.read().await.get(&index) {
            vec.extend(existing.to_owned());
        }

        self.indexed.write().await.insert(index, vec);

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    async fn get_indexed(&self, type_: &str, format: &str) -> Vec<String> {
        let index = format!("{}:{}", type_, format);
        let map = self.indexed.read().await;
        let vec = map.get(&index);
        vec.cloned().unwrap_or_else(Vec::new)
    }

    #[cfg(test)]
    pub(crate) async fn store_entry(&self, entry: &CredentialEntry) -> Result<String, Error> {
        let credential = entry.credential.to_owned();
        let kid = entry.kid.to_owned();

        use crate::vc::core::api::KeyMetadata;
        use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};

        let metadata = DefaultMetadataProcessor::resolve_metadata(
            &credential,
            KeyMetadata {
                did_url: "to-be-ignored".to_string(),
                kid,
            },
        )
        .unwrap();

        self.store_credential(credential, &metadata).await
    }

    #[cfg(test)]
    pub(crate) async fn store_entries(
        &self,
        entries: Vec<&CredentialEntry>,
    ) -> Result<Vec<String>, Error> {
        future::try_join_all(entries.iter().map(|entry| self.store_entry(entry))).await
    }
}

#[async_trait]
impl Vault for InMemVault {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: &CredentialMetadata,
    ) -> Result<String, Error> {
        let storage_id = random_string::generate(5, random_string::charsets::ALPHA);

        let entry = CredentialEntry {
            credential,
            kid: metadata.kid.clone(),
        };

        let _ = self
            .storage
            .put(storage_id.clone(), entry)
            .await
            .map_err(|err| {
                StoringSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        self.update_index(metadata, &storage_id).await?;

        Ok(storage_id)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn get_credential(&self, id: &str) -> Result<Option<CredentialEntry>, Error> {
        self.storage.get(&id.to_string()).await.map_err(|err| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn find_credentials(
        &self,
        criteria: FindCriteria,
    ) -> Result<Vec<CredentialEntry>, Error> {
        let creds = match criteria {
            FindCriteria::ByTypeAndFormat(type_, fmt) => {
                let ids = self.get_indexed(&type_, &fmt).await;
                future::try_join_all(ids.iter().map(|id| self.get_credential(id))).await?
            }
        };

        Ok(creds.into_iter().flatten().collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::inmem::vault::InMemVault;
    use crate::vault::test_util::test_vault;

    #[tokio::test]
    async fn e2e() {
        let vault = InMemVault::new();
        test_vault(vault).await;
    }
}
