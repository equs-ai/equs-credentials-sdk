use crate::inmem::storage::InMemStorage;
use crate::inmem::tag::TagStorage;
use crate::inmem::utils::intersection;
use crate::storage::Storage;
use crate::vault::{CredentialEntry, CredentialFilter, Error, StoringSnafu, Vault};
use crate::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use futures::future;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{instrument, Level};

#[derive(Debug, Clone)]
pub struct InMemVault {
    storage: Arc<InMemStorage<String, CredentialEntry>>,
    indexes: TagStorage,
}

impl InMemVault {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(InMemStorage::new()),
            indexes: TagStorage::new(),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    async fn update_index(&self, metadata: &CredentialMetadata, storage_id: &str) {
        self.indexes
            .put_tag(&("type".to_string(), metadata.type_.to_owned()), storage_id)
            .await;
        self.indexes
            .put_tag(
                &("format".to_string(), metadata.format.to_string()),
                storage_id,
            )
            .await;

        for tag in &metadata.tags {
            let (name, _) = tag;
            self.indexes.put_tag(tag, storage_id).await;
            self.indexes
                .put_tag_name(name.to_string(), storage_id)
                .await;
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
    async fn find_by_filters(&self, filters: CredentialFilter) -> HashSet<String> {
        match filters {
            CredentialFilter::Format(format) => {
                self.indexes.get_ids(&("format".to_string(), format)).await
            }
            CredentialFilter::TagKeys(tag_names) => {
                self.indexes.get_ids_for_tag_names(tag_names).await
            }
            CredentialFilter::Tag(name, val) => self.indexes.get_ids(&(name, val)).await,
        }
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
    async fn get_credentials(&self) -> Result<Vec<CredentialEntry>, Error> {
        self.storage.get_all().await.map_err(|err| {
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
        filters: Vec<CredentialFilter>,
    ) -> Result<Vec<CredentialEntry>, Error> {
        let ids = future::join_all(
            filters
                .into_iter()
                .map(|filter| self.find_by_filters(filter)),
        )
        .await;

        let ids = intersection(&ids);

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
