use crate::inmem::storage::InMemStorage;
use crate::storage::Storage;
use crate::vault::{CredentialEntry, CredentialFilter, Error, StoringSnafu, Vault};
use crate::vc::{Credential, CredentialMetadata};
use async_rwlock::RwLock;
use async_trait::async_trait;
use futures::future;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{instrument, Level};

#[derive(Debug, Clone)]
pub struct InMemVault {
    storage: Arc<InMemStorage<String, CredentialEntry>>,
    indexes: Index,
}

#[derive(Debug, Clone)]
struct Index {
    tags: Arc<RwLock<HashMap<String, Vec<String>>>>,
    tag_names: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

pub type Tag = (String, String);

impl Index {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn new() -> Self {
        Self {
            tags: Arc::new(RwLock::new(HashMap::new())),
            tag_names: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    async fn put_tag(&self, tag: &Tag, storage_id: &str) {
        let (k, v) = tag;
        let index = format!("{k}:{v}");

        let mut vec: Vec<String> = vec![];
        vec.push(storage_id.to_owned());

        if let Some(existing) = self.tags.read().await.get(&index) {
            vec.extend(existing.to_owned());
        }

        self.tags.write().await.insert(index, vec);
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    async fn put_tag_name(&self, tag_name: String, storage_id: &str) {
        let mut vec: Vec<String> = vec![];
        vec.push(storage_id.to_owned());

        if let Some(existing) = self.tag_names.read().await.get(&tag_name) {
            vec.extend(existing.to_owned());
        }

        self.tag_names.write().await.insert(tag_name, vec);
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    async fn get_ids(&self, tag: &Tag) -> HashSet<String> {
        let (k, v) = tag;
        let index = format!("{k}:{v}");

        let vec = self.tags.read().await.get(&index);

        let mut ids = HashSet::new();
        if let Some(existing) = self.tags.read().await.get(&index) {
            ids.extend(existing.to_owned())
        }

        ids
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    async fn get_ids_for_tag_names(&self, tag_names: Vec<String>) -> HashSet<String> {
        let map = self.tag_names.read().await;

        let mut ids = HashSet::new();

        for tag_name in tag_names.iter() {
            let tag_ids = map.get(tag_name).cloned().unwrap_or(Vec::new());
            ids.extend(tag_ids);
        }

        ids
    }

    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn find_by_filters(&self, filters: CredentialFilter) -> HashSet<String> {
        match filters {
            CredentialFilter::Format(format) => self.get_ids(&("format".to_string(), format)).await,
            CredentialFilter::TagKeys(tag_names) => self.get_ids_for_tag_names(tag_names).await,
            CredentialFilter::Tag(name, val) => self.get_ids(&(name, val)).await,
        }
    }
}

#[instrument(level = Level::TRACE, ret())]
fn intersection(id_sets: &[HashSet<String>]) -> HashSet<String> {
    if let Some(first) = id_sets.first() {
        // intersection of all sets
        return first
            .iter()
            .filter(|elem| id_sets.iter().all(|set| set.contains(*elem)))
            .map(|elem| elem.to_owned())
            .collect::<HashSet<String>>();
    }

    HashSet::new()
}

impl InMemVault {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(InMemStorage::new()),
            indexes: Index::new(),
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
    async fn find_credentials(
        &self,
        filters: Vec<CredentialFilter>,
    ) -> Result<Vec<CredentialEntry>, Error> {
        let mut ids_per_criteria = vec![];
        for filter in filters {
            let found = self.indexes.find_by_filters(filter.clone()).await;
            ids_per_criteria.push(found.clone());
        }

        let ids = intersection(&ids_per_criteria);

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
