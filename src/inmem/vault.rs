use crate::inmem::index_storage::IndexStorage;
use crate::inmem::storage::InMemStorage;
use crate::storage::Storage;
use crate::vault::{
    CredentialEntry, DeletingSnafu, EmptyFieldsSnafu, Error, ResolvingSnafu, StoringSnafu, Vault,
    VaultFetchOptions,
};
use crate::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use futures::future;
use rand::Rng;
use rand::distr::Alphanumeric;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{Level, instrument};

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
    pub(crate) async fn store_entry(
        &self,
        entry: &CredentialEntry,
        did_url: String,
    ) -> Result<String, Error> {
        let credential = entry.credential.to_owned();
        let kid = entry.kid.to_owned();

        use crate::vc::core::api::KeyMetadata;
        use crate::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};

        let metadata =
            DefaultMetadataProcessor::resolve_metadata(&credential, KeyMetadata { did_url, kid })
                .unwrap();

        self.store_credential(credential, &metadata).await
    }

    #[cfg(test)]
    pub(crate) async fn store_entries(
        &self,
        entries: Vec<(&CredentialEntry, &str)>,
    ) -> Result<Vec<String>, Error> {
        future::try_join_all(
            entries
                .iter()
                .map(|(entry, did_url)| self.store_entry(entry, did_url.to_string())),
        )
        .await
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
        let storage_id = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect::<String>();

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
    async fn get_credentials(
        &self,
        pagination: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>, Error> {
        let mut elements = self.storage.get_all().await.map_err(|err| {
            ResolvingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        if let Some(pagination) = pagination {
            let elements_amount = elements.len();
            elements = elements
                .into_iter()
                .skip(pagination.offset.unwrap_or(0))
                .take(pagination.limit.unwrap_or(elements_amount))
                .collect::<Vec<CredentialEntry>>();
        }

        Ok(elements)
    }

    async fn find_credentials(
        &self,
        fields: Vec<String>,
        pagination: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>, Error> {
        if fields.is_empty() {
            EmptyFieldsSnafu.fail()?
        };

        let ids = self.find_by_fields(fields).await;
        let creds = future::try_join_all(ids.iter().map(|id| self.get_credential(id))).await?;

        let result = if let Some(pagination) = pagination {
            let credentials_amount = creds.len();
            creds
                .into_iter()
                .flatten()
                .skip(pagination.offset.unwrap_or(0))
                .take(pagination.limit.unwrap_or(credentials_amount))
                .collect::<Vec<CredentialEntry>>()
        } else {
            creds.into_iter().flatten().collect()
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::inmem::vault::InMemVault;
    use crate::vault::test_util::test_vault;
    use crate::vault::{Vault, VaultFetchOptions};
    use crate::vc::{Credential, CredentialMetadata, VCFormat};
    use rstest::rstest;

    #[tokio::test]
    async fn e2e() {
        let vault = InMemVault::new();
        test_vault(vault).await;
    }

    #[tokio::test]
    async fn get_credentials_without_pagination_returns_all_credentials() {
        let vault = InMemVault::new();

        for _ in 0..10 {
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_empty_credential_metadata_sd_jwt(),
                )
                .await
                .unwrap();
        }
        let credentials = vault.get_credentials(None).await.unwrap();

        assert_eq!(credentials.len(), 10);
    }
    #[rstest]
    #[case(0, 5)]
    #[case(0, 10)]
    #[case(10, 11)]
    #[case(3, 3)]
    #[tokio::test]
    async fn get_credentials_with_pagination_succeed(#[case] offset: usize, #[case] limit: usize) {
        let amount_to_store: usize = 10;

        let remaining_amount = amount_to_store.saturating_sub(offset);

        let amount_to_get_from_vault = if remaining_amount > limit {
            limit
        } else {
            remaining_amount
        };

        let vault = InMemVault::new();

        for _ in 0..amount_to_store {
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_empty_credential_metadata_sd_jwt(),
                )
                .await
                .unwrap();
        }
        let credentials = vault
            .get_credentials(Some(VaultFetchOptions {
                offset: Some(offset),
                limit: Some(limit),
            }))
            .await
            .unwrap();

        assert_eq!(credentials.len(), amount_to_get_from_vault);
    }

    #[tokio::test]
    async fn find_credentials_without_pagination_returns_all_credentials() {
        let vault = InMemVault::new();

        for _ in 0..10 {
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_credential_metadata_sd_jwt_with_fields(),
                )
                .await
                .unwrap();
        }
        let credentials = vault
            .find_credentials(vec!["$.vct".to_string()], None)
            .await
            .unwrap();

        assert_eq!(credentials.len(), 10);
    }

    #[rstest]
    #[case(vec!["$.vct".to_string()], 0, 5, 5)]
    #[case(vec!["$.fake".to_string()], 0, 5, 0)]
    #[case(vec!["$.vct".to_string()], 3, 3, 3)]
    #[case(vec!["$.vct".to_string()], 7, 5, 3)]
    #[tokio::test]
    async fn find_credentials_with_pagination_succeeds(
        #[case] fields: Vec<String>,
        #[case] offset: usize,
        #[case] limit: usize,
        #[case] result_amount: usize,
    ) {
        let vault = InMemVault::new();

        for _ in 0..10 {
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_credential_metadata_sd_jwt_with_fields(),
                )
                .await
                .unwrap();
        }
        let credentials = vault
            .find_credentials(
                fields,
                Some(VaultFetchOptions {
                    offset: Some(offset),
                    limit: Some(limit),
                }),
            )
            .await
            .unwrap();

        assert_eq!(credentials.len(), result_amount);
    }

    fn get_credential_sd_jwt() -> Credential {
        Credential::SdJwt("token".to_string())
    }
    fn get_empty_credential_metadata_sd_jwt() -> CredentialMetadata {
        CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid: "1234".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            fields: vec![],
        }
    }
    fn get_credential_metadata_sd_jwt_with_fields() -> CredentialMetadata {
        CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid: "1234".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            fields: vec![
                "$.vct".to_string(),
                "$.name".to_string(),
                "$.email.work".to_string(),
            ],
        }
    }
}
