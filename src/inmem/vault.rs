use crate::inmem::index_storage::IndexStorage;
use crate::inmem::storage::InMemStorage;
use crate::storage::Storage;
use crate::vault::{
    CredentialEntry, DeletingSnafu, EmptyFieldsSnafu, Error, ResolvingSnafu, StoringSnafu, Vault,
};
use crate::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use futures::future;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{instrument, Level};

type Level_ = Level;

#[derive(Debug, Clone)]
pub struct InMemVault {
    storage: Arc<InMemStorage<String, CredentialEntry>>,
    indexes: IndexStorage,
}

impl InMemVault {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(InMemStorage::new()),
            indexes: IndexStorage::new(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    async fn update_index(&self, metadata: &CredentialMetadata, storage_id: &str) {
        for field in &metadata.fields {
            self.indexes.put_index(field.to_owned(), storage_id).await;
        }
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

    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn find_by_fields(&self, fields: Vec<String>) -> HashSet<String> {
        self.indexes.get_ids_for_indexes(fields).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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
            id: storage_id.clone(),
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

        self.update_index(metadata, &storage_id).await;

        Ok(storage_id)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn delete_credential(&self, id: &str) -> Result<(), Error> {
        self.storage.delete(&id.to_string()).await.map_err(|err| {
            DeletingSnafu {
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
    async fn get_credential(&self, id: &str) -> Result<Option<CredentialEntry>, Error> {
        self.storage.get(&id.to_string()).await.map_err(|err| {
            ResolvingSnafu {
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
    async fn get_credentials(&self) -> Result<Vec<CredentialEntry>, Error> {
        self.storage.get_all().await.map_err(|err| {
            ResolvingSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }

    async fn find_credentials(&self, fields: Vec<String>) -> Result<Vec<CredentialEntry>, Error> {
        if fields.is_empty() {
            EmptyFieldsSnafu.fail()?
        };

        let ids = self.find_by_fields(fields).await;
        let creds = future::try_join_all(ids.iter().map(|id| self.get_credential(id))).await?;
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
