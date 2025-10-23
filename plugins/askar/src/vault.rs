use aries_askar::entry::{Entry, EntryKind, EntryTag, TagFilter};
use aries_askar::storage::backend::OrderBy;
use async_trait::async_trait;
use snafu::ensure;
use tracing::{Level, instrument};
use uuid::Uuid;

use crate::{AskarStorage, AskarStorageScan, AskarStorageScanParams};
use agent_sdk::crypto::Alg;
use agent_sdk::vault::{
    DeletingSnafu, EmptyFieldsSnafu, Error, FetchingSnafu, FormatNotSupportedSnafu, ResolvingSnafu,
    StoringSnafu, VCSnafu,
};
use agent_sdk::vc::{JWT_VC_JSON, JWT_VC_JSON_LD, LDP_VC, SD_JWT_VC};

pub use agent_sdk::vault::{CredentialEntry, Vault, VaultPagination};
pub use agent_sdk::vc::{Credential, CredentialMetadata, HasVCFormat, VCFormat};

pub const TAG_TYPE: &str = "type_";
pub const TAG_FORMAT: &str = "format";
pub const TAG_KID: &str = "kid";
pub const TAG_ALG: &str = "alg";

#[derive(Debug)]
pub struct AskarVaultCursorParams {
    pub fields: Vec<String>,
    pub batch_size: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub order_by: Option<AskarVaultCursorParamsOrderBy>,
    pub sort_by_desc: Option<AskarVaultCursorParamsSortBy>,
}

pub type AskarVaultCursorParamsOrderBy = OrderBy;

#[derive(Debug)]
pub enum AskarVaultCursorParamsSortBy {
    Ascending,
    Descending,
}

#[derive(Clone, Debug)]
pub struct AskarVault(AskarStorage);

impl AskarVault {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new(storage: AskarStorage) -> Self {
        AskarVault(storage)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self, params),
        err(),
    )]
    pub async fn create_cursor<'a>(
        &self,
        params: AskarVaultCursorParams,
    ) -> Result<AskarVaultCursor<'a>, aries_askar::Error> {
        let batch_size = params.batch_size.map(|b| b as usize);
        let storage_scan = self.0.scan(params.into()).await?;

        Ok(AskarVaultCursor::new(storage_scan, batch_size))
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    pub async fn count_all(&self, category: Option<String>) -> Result<i64, aries_askar::Error> {
        let mut seesion = self.0.session().await?;
        seesion.count(category.as_deref(), None).await
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub async fn close_vault(self) -> Result<(), aries_askar::Error> {
        self.0.close().await
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn insert(&self, entity: &Entry) -> Result<AskarVaultId, aries_askar::Error> {
        let mut session = self.0.session().await?;

        session
            .insert(
                &entity.category,
                &entity.name,
                &entity.value,
                Some(&entity.tags),
                None,
            )
            .await?;
        session.commit().await?;

        Ok(AskarVaultId(
            entity.category.to_owned(),
            entity.name.to_owned(),
        ))
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn remove(&self, id: AskarVaultId) -> Result<(), aries_askar::Error> {
        let mut session = self.0.session().await?;
        session.remove(id.category(), id.name()).await?;
        session.commit().await?;

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn get(&self, id: AskarVaultId) -> Result<Option<Entry>, aries_askar::Error> {
        let mut seesion = self.0.session().await?;
        seesion.fetch(id.category(), id.name(), false).await
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn get_all(&self) -> Result<Vec<Entry>, aries_askar::Error> {
        let mut session = self.0.session().await?;
        session
            .fetch_all(None, None, None, Some(OrderBy::Id), false, false)
            .await
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn find(&self, filter: TagFilter) -> Result<Vec<Entry>, aries_askar::Error> {
        let mut session = self.0.session().await?;
        session
            .fetch_all(None, Some(filter), None, None, false, false)
            .await
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn get_with_pagination(
        self,
        filter: Option<TagFilter>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<Entry>, aries_askar::Error> {
        let mut cursor = self
            .0
            .store
            .scan(
                Some(self.0.profile),
                None,
                filter,
                Some(offset as i64),
                Some(limit as i64),
                Some(OrderBy::Id),
                false,
            )
            .await?;

        // No close method for cursor but it only returns limited number of elements skipping first elements regarding to offset & limit parameters. Connection pool is open until every element is consumed
        // TODO Close cursor when method appears
        Ok(cursor.fetch_next().await?.unwrap_or(Default::default()))
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    fn create_entry(
        credential: &Credential,
        metadata: &CredentialMetadata,
    ) -> Result<Entry, Error> {
        let name = Uuid::new_v4().to_string();
        let mut tags = vec![EntryTag::Encrypted(
            TAG_KID.to_string(),
            metadata.kid.to_owned(),
        )];

        if let Some(alg) = metadata.alg {
            tags.push(EntryTag::Encrypted(
                TAG_ALG.to_string(),
                <Alg as Into<&str>>::into(alg).to_string(),
            ))
        }

        for tag in &metadata.fields {
            tags.push(EntryTag::Encrypted(tag.to_owned(), "".to_owned()))
        }

        match credential {
            Credential::JwtVcJson(credential) => Ok(Entry::new(
                EntryKind::Item,
                JWT_VC_JSON,
                name,
                credential.as_str(),
                tags,
            )),
            Credential::JwtVcJsonLd(credential) => Ok(Entry::new(
                EntryKind::Item,
                JWT_VC_JSON_LD,
                name,
                credential.as_str(),
                tags,
            )),
            Credential::LdpVc(credential) => {
                let credential_json = serde_json::to_string(&credential).map_err(|err| {
                    VCSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;
                Ok(Entry::new(
                    EntryKind::Item,
                    LDP_VC,
                    name,
                    credential_json,
                    tags,
                ))
            }
            Credential::SdJwt(credential) => Ok(Entry::new(
                EntryKind::Item,
                SD_JWT_VC,
                name,
                credential.as_str(),
                tags,
            )),
            _ => FormatNotSupportedSnafu {
                format: format!("{:?}", credential),
            }
            .fail(),
        }
    }
}

#[async_trait]
impl Vault for AskarVault {
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
        let entry = Self::create_entry(&credential, metadata)?;
        let id = self.insert(&entry).await.map_err(|err| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(id.into())
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn delete_credential(&self, id: &str) -> Result<(), Error> {
        self.remove(id.try_into()?).await.map_err(|err| {
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
        let entry = self.get(id.try_into()?).await.map_err(|err| {
            ResolvingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        entry.map(entry_to_credential).transpose()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn get_credentials(
        &self,
        pagination: Option<VaultPagination>,
    ) -> Result<Vec<CredentialEntry>, Error> {
        let entries = if let Some(pagination) = pagination {
            self.to_owned()
                .get_with_pagination(None, pagination.skip_amount(), pagination.batch_size)
                .await
        } else {
            self.get_all().await
        }
        .map_err(|err| {
            ResolvingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        entries.into_iter().map(entry_to_credential).collect()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn find_credentials(
        &self,
        fields: Vec<String>,
        pagination: Option<VaultPagination>,
    ) -> Result<Vec<CredentialEntry>, Error> {
        if fields.is_empty() {
            EmptyFieldsSnafu.fail()?
        };

        let tag_filter = map_credential_fields_to_tags(fields).ok_or_else(|| {
            ResolvingSnafu {
                details: "empty tag filter",
            }
            .build()
        })?;

        let entries = if let Some(pagination) = pagination {
            self.to_owned()
                .get_with_pagination(
                    Some(tag_filter),
                    pagination.skip_amount(),
                    pagination.batch_size,
                )
                .await
        } else {
            self.find(tag_filter).await
        }
        .map_err(|err| {
            ResolvingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;
        entries.into_iter().map(entry_to_credential).collect()
    }
}

#[derive(Debug)]
struct AskarVaultId(String, String);

impl AskarVaultId {
    #[allow(dead_code)] // todo fix
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new(category: String, name: String) -> Self {
        AskarVaultId(category, name)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    pub fn category(&self) -> &str {
        &self.0
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    pub fn name(&self) -> &str {
        &self.1
    }
}

impl TryFrom<&str> for AskarVaultId {
    type Error = Error;

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts = value.split(':').collect::<Vec<&str>>();

        ensure!(
            parts.len() == 2,
            ResolvingSnafu {
                details: format!("Incorrect ID: {}", value)
            }
        );

        let category = parts[0].to_string();
        let name = parts[1].to_string();

        Ok(AskarVaultId(category, name))
    }
}

impl From<AskarVaultId> for String {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn from(value: AskarVaultId) -> Self {
        format!("{}:{}", value.0, value.1)
    }
}

pub struct AskarVaultCursor<'a> {
    inner: AskarStorageScan<'a>,
    batch_size: usize,
    last_remained_entries: Option<Vec<Entry>>,
}

const DEFAULT_BATCH_SIZE: usize = 32;

impl<'a> AskarVaultCursor<'a> {
    pub fn new(storage_scan: AskarStorageScan<'a>, batch_size: Option<usize>) -> Self {
        Self {
            inner: storage_scan,
            batch_size: batch_size.unwrap_or(DEFAULT_BATCH_SIZE),
            last_remained_entries: None,
        }
    }

    /// Fetches the next batch of credentials from the vault storage cursor.
    ///
    /// This method implements batched retrieval of credentials by making the following steps:
    /// 1. Pre-allocates vector capacity to match batch size
    /// 2. Processes any remaining entries from previous fetch first
    /// 3. Fetches new entries from vault until batch size is reached
    /// 4. Stores any excess entries for the next fetch operation
    ///
    /// # Returns
    /// An array of [CredentialEntry] on success.
    /// In case if there are no credential entries [None] should be returned.
    ///
    /// # Errors
    ///
    /// * [Error::VC] - fails to fetch VCs from vault.
    /// * [Error::Resolving] - fails to resolve vault entry.
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    pub async fn fetch_next(&mut self) -> Result<Option<Vec<CredentialEntry>>, Error> {
        if self.batch_size == 0 {
            return Ok(None);
        }

        let mut credentials = self.process_remained_entries()?;

        if credentials.len() == self.batch_size {
            return Ok(Some(credentials));
        }

        self.fetch_entries_until_batch_size(&mut credentials)
            .await?;

        if credentials.is_empty() {
            return Ok(None);
        }

        Ok(Some(credentials))
    }

    fn process_remained_entries(&mut self) -> Result<Vec<CredentialEntry>, Error> {
        let mut credentials = Vec::with_capacity(self.batch_size);

        if let Some(mut remained_entries) = self.last_remained_entries.take() {
            if remained_entries.len() > self.batch_size {
                let remained = remained_entries.split_off(self.batch_size);
                self.last_remained_entries = Some(remained);
            }

            for entry in remained_entries {
                credentials.push(entry_to_credential(entry)?);
            }
        }

        Ok(credentials)
    }

    async fn fetch_entries_until_batch_size(
        &mut self,
        credentials: &mut Vec<CredentialEntry>,
    ) -> Result<(), Error> {
        while credentials.len() < self.batch_size {
            let entries = self.inner.fetch_next().await.map_err(|err| {
                FetchingSnafu {
                    details: format!("Failed to fetch credentials: {err}"),
                }
                .build()
            })?;

            let Some(mut entries) = entries else {
                return Ok(());
            };

            let remained_space = self.batch_size - credentials.len();
            if remained_space == 0 {
                return Ok(());
            }

            if entries.len() > remained_space {
                let remained_entries = entries.split_off(remained_space);
                self.last_remained_entries = Some(remained_entries);
            }

            for entry in entries {
                credentials.push(entry_to_credential(entry)?);
            }
        }
        Ok(())
    }
}

impl From<AskarVaultCursorParams> for AskarStorageScanParams {
    fn from(value: AskarVaultCursorParams) -> Self {
        AskarStorageScanParams {
            limit: value.limit,
            offset: value.offset,
            tag_filter: map_credential_fields_to_tags(value.fields),
            order_by: value.order_by,
            sort_by_desc: value.sort_by_desc.map(|s| match s {
                AskarVaultCursorParamsSortBy::Ascending => false,
                AskarVaultCursorParamsSortBy::Descending => true,
            }),
        }
    }
}

#[instrument(level = Level::TRACE, ret())]
fn map_credential_fields_to_tags(fields: Vec<String>) -> Option<TagFilter> {
    // TODO we use exist but it requires Vec<String>. A bit of confusable. Search for better solution
    let tags = fields
        .iter()
        .map(|field| TagFilter::exist(vec![field.to_owned()]))
        .collect::<Vec<TagFilter>>();

    if tags.is_empty() {
        return None;
    }

    Some(TagFilter::any_of(tags))
}

fn entry_to_credential(entry: Entry) -> Result<CredentialEntry, Error> {
    let credential_str = entry
        .value
        .as_opt_str()
        .ok_or_else(|| {
            VCSnafu {
                details: "Failed to convert secret bytes to credential string",
            }
            .build()
        })?
        .to_string();

    let credential = match entry.category.as_str() {
        JWT_VC_JSON => Credential::JwtVcJson(credential_str),
        JWT_VC_JSON_LD => Credential::JwtVcJsonLd(credential_str),
        LDP_VC => {
            let credential = serde_json::from_str(&credential_str).map_err(|err| {
                VCSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;
            Credential::LdpVc(credential)
        }
        SD_JWT_VC => Credential::SdJwt(credential_str),
        _ => FormatNotSupportedSnafu {
            format: entry.category.clone(),
        }
        .fail()?,
    };

    let kid = entry
        .tags
        .iter()
        .find(|t| t.name() == TAG_KID)
        .ok_or(
            ResolvingSnafu {
                details: "KID not specified",
            }
            .build(),
        )?
        .value()
        .to_owned();

    Ok(CredentialEntry {
        credential,
        kid,
        id: AskarVaultId(entry.category, entry.name).into(),
    })
}

#[cfg(test)]
mod tests {
    use crate::vault::{
        AskarVault, AskarVaultCursorParams, AskarVaultCursorParamsOrderBy,
        AskarVaultCursorParamsSortBy,
    };
    use crate::{AskarStorage, AskarStorageConfig, KeyMethod};
    use agent_sdk::vault::{CredentialEntry, Vault, VaultPagination};
    use agent_sdk::vc::{Credential, CredentialMetadata, VCFormat};
    use rstest::rstest;

    const CRED_SD_JWT: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiN6RG5hZXVqUHFaNUVqSG1ma3J6WXdlTGZNcXI4YXFBM290M0J0YzRGZTl0eUxxa21SIn0.eyJfc2QiOlsiQ1Q1bzFMZk5XRE9LT3h4NDJCWUc0NzU0bFpIeTZ0MG5PUGtGRWRmb3FvTSIsIks3bWEwTmZxR0NfM0xQdG12cWtySTR5ckpsdkg0VFU2OWU3SXYtN0VJbzQiLCJyZVlhTkZCV0h6VjE3Y3Z1cTNyRmpVSTNHeDVKc19EbW5VWlNFUmQ0aFpzIl0sInZjdCI6IlNEX0pXVF9jcmVkIiwic3ViIjoiZGlkOmtleTp6RG5hZW5wbnRDa1huRENuYURrNjJMeE5xUGM0Q01kMzJmYmhpVnNaVjVLcFBURzJjIiwibmJmIjoxNzI1NTMzMjU0LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV1alBxWjVFakhtZmtyell3ZUxmTXFyOGFxQTNvdDNCdGM0RmU5dHlMcWttUiIsImlhdCI6MTcyNTUzMzI1NCwiZXhwIjoxNzU3MDY5MjU0LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiVExuNjZxYm5QZXhLeUZtZ3h1Y1kzSlpyZHhCRGpBc3ItbXkya1dBYms4ayIsInkiOiJzaFl6eUVUOENyWVcyTXhPU0FCSkxhbUpPTGV3LWpQbE9aeHdTUzZrWGdjIn19fQ.CBBzIiTjRs2bmKENQcRY14wVnl2vnIjJY9u3AYrA9KQDjqCXZXSzoxQlripAM6Ud_QaYNrZcHK2EVo4QlH3k9w~WyJvMFR4dEw4QWh1TFJXUmduSDk4NF9RIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ2SVMzZXNQTHlRUHRRZ0JMZ09GYWFnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJsaW81cXNVZHZJX3V3eUdiRmFtTnFRIiwgImRvYiIsICIwOS8wOS8xOTg5Il0~";
    const CRED_LDP_VC: &str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;

    // TODO: consider splitting this test into several small unit tests
    #[tokio::test]
    async fn test_askar_vault() {
        let vault = create_test_vault().await;

        test_vault(&vault).await;

        vault.close_vault().await.unwrap();
    }

    #[rstest]
    #[case(vec!["$.name".to_string(), "$.email.work".to_string(), "$.vct".to_string()])]
    #[case(vec!["$.name".to_string(), "$.email.work1".to_string(), "$.vct2".to_string()])]
    #[case(vec!["$.name".to_string()])]
    #[should_panic(expected = "left: Array []")]
    #[case(vec!["$.name1".to_string()])]
    #[should_panic(expected = "left: Array []")]
    #[case(vec!["$.name1".to_string(), "$.email.work2".to_string(), "$.vct3".to_string()])]
    #[tokio::test]
    async fn askar_vault_mapping_credentials_uses_disjunction(#[case] fields: Vec<String>) {
        let vault = create_test_vault().await;
        let sd_jwt_cred_id = store_sd_jwt_to_vault(&vault).await;

        let find_res = vault.find_credentials(fields, None).await.unwrap();

        assert_eq!(
            serde_json::to_value(find_res).unwrap(),
            serde_json::to_value(vec![create_expected_entry_sd_jwt(sd_jwt_cred_id)]).unwrap()
        );
    }

    #[tokio::test]
    async fn get_credentials_without_pagination_returns_all_credentials() {
        let vault = create_test_vault().await;

        for i in 0..10 {
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_empty_credential_metadata_sd_jwt(i.to_string()),
                )
                .await
                .unwrap();
        }
        let credentials = vault.get_credentials(None).await.unwrap();

        assert_eq!(credentials.len(), 10);
    }

    #[rstest]
    #[case(10, 0, 5, 5)]
    #[case(10, 0, 10, 10)]
    #[case(10, 10, 11, 0)]
    #[case(10, 3, 3, 1)]
    #[tokio::test]
    async fn get_credentials_with_pagination_succeed(
        #[case] amount_to_store: usize,
        #[case] page: usize,
        #[case] batch_size: usize,
        #[case] amount_to_get_from_vault: usize,
    ) {
        let vault = create_test_vault().await;

        let mut page_index = 0;

        for i in 1..amount_to_store + 1 {
            if i % batch_size == 0 {
                page_index += 1
            }
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_empty_credential_metadata_sd_jwt(page_index.to_string()),
                )
                .await
                .unwrap();
        }
        let credentials = vault
            .get_credentials(Some(VaultPagination::new(page, batch_size)))
            .await
            .unwrap();

        assert_eq!(credentials.len(), amount_to_get_from_vault);
        if amount_to_get_from_vault != 0 {
            assert_eq!(credentials.first().unwrap().kid, page.to_string());
        }
    }

    #[tokio::test]
    async fn find_credentials_without_pagination_returns_all_credentials() {
        let vault = create_test_vault().await;

        for i in 0..10 {
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_credential_metadata_sd_jwt_with_fields(i.to_string()),
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
    #[case(vec!["$.vct".to_string()], 3, 3, 1)]
    #[case(vec!["$.vct".to_string()], 5, 3, 0)]
    #[tokio::test]
    async fn find_credentials_with_pagination_succeeds(
        #[case] fields: Vec<String>,
        #[case] page: usize,
        #[case] batch_size: usize,
        #[case] result_amount: usize,
    ) {
        let vault = create_test_vault().await;

        for i in 0..10 {
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_credential_metadata_sd_jwt_with_fields(i.to_string()),
                )
                .await
                .unwrap();
        }
        let credentials = vault
            .find_credentials(fields, Some(VaultPagination::new(page, batch_size)))
            .await
            .unwrap();

        assert_eq!(credentials.len(), result_amount);
    }

    #[rstest]
    #[case::two_feth_calls_with_last_one_is_less_than_batch_size(Some(65), Some(33), vec![33, 32])]
    #[case::first_also_the_last_fetch(Some(50), Some(50), vec![50])]
    #[case::multiple_fetches(Some(100), Some(20), vec![20, 20, 20, 20, 20])]
    #[case::without_predefined_limit(None, Some(32), vec![32, 32, 32, 4])]
    #[case::without_predefined_limit_and_non_default_batch_size(None, Some(64), vec![64, 36])]
    #[case::without_default_batch_size(None, None, vec![32, 32, 32, 4])]
    #[case::with_limit_greater_than_total(Some(101), Some(33), vec![33, 33, 33, 1])]
    #[case::with_limit_less_than_batch_size(Some(32), Some(33), vec![32])]
    #[tokio::test]
    async fn fetch_next_by_cursor_works_correctly(
        #[case] limit: Option<i64>,
        #[case] batch_size: Option<i64>,
        #[case] expected_batches: Vec<usize>,
    ) {
        let vault = create_test_vault().await;

        store_batch_of_credentials(&vault, 100).await;
        let mut cursor = vault
            .create_cursor(AskarVaultCursorParams {
                fields: vec!["$.vct".to_string()],
                batch_size,
                limit,
                offset: None,
                order_by: Some(AskarVaultCursorParamsOrderBy::Id),
                sort_by_desc: None,
            })
            .await
            .unwrap();

        for expected_size in expected_batches {
            let batch = cursor.fetch_next().await.unwrap().unwrap();
            assert_eq!(batch.len(), expected_size);
        }
        assert!(cursor.fetch_next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fetch_next_by_cursor_with_offset_works() {
        let vault = create_test_vault().await;

        store_batch_of_credentials(&vault, 10).await;

        let mut cursor = vault
            .create_cursor(AskarVaultCursorParams {
                fields: vec!["$.vct".to_string()],
                batch_size: Some(5),
                limit: None,
                offset: Some(5),
                order_by: Some(AskarVaultCursorParamsOrderBy::Id),
                sort_by_desc: None,
            })
            .await
            .unwrap();

        let batch = cursor.fetch_next().await.unwrap().unwrap();
        assert_eq!(batch.len(), 5);
        assert!(cursor.fetch_next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fetch_next_by_cursor_with_sort_desc_works() {
        let vault = create_test_vault().await;

        store_batch_of_credentials(&vault, 5).await;

        let mut cursor = vault
            .create_cursor(AskarVaultCursorParams {
                fields: vec!["$.vct".to_string()],
                batch_size: Some(5),
                limit: None,
                offset: None,
                order_by: Some(AskarVaultCursorParamsOrderBy::Id),
                sort_by_desc: Some(AskarVaultCursorParamsSortBy::Descending),
            })
            .await
            .unwrap();

        let batch = cursor.fetch_next().await.unwrap().unwrap();
        assert_eq!(batch.len(), 5);
        assert_eq!(batch[0].kid, "4");
        assert_eq!(batch[4].kid, "0");
    }

    #[tokio::test]
    async fn fetch_next_by_cursor_returns_none_for_empty_vault() {
        let vault = create_test_vault().await;
        let mut cursor = vault
            .create_cursor(AskarVaultCursorParams {
                fields: vec![],
                batch_size: Some(5),
                limit: None,
                offset: None,
                order_by: Some(AskarVaultCursorParamsOrderBy::Id),
                sort_by_desc: None,
            })
            .await
            .unwrap();

        assert!(cursor.fetch_next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fetch_next_by_cursor_filtering_works() {
        let vault = create_test_vault().await;

        store_batch_of_credentials(&vault, 5).await;

        let mut cursor = vault
            .create_cursor(AskarVaultCursorParams {
                fields: vec!["$.custom_claim".to_string()],
                batch_size: Some(5),
                limit: None,
                offset: None,
                order_by: Some(AskarVaultCursorParamsOrderBy::Id),
                sort_by_desc: None,
            })
            .await
            .unwrap();

        assert!(cursor.fetch_next().await.unwrap().is_none());
    }

    fn get_credential_sd_jwt() -> Credential {
        Credential::SdJwt(CRED_SD_JWT.to_string())
    }
    fn get_empty_credential_metadata_sd_jwt(kid: String) -> CredentialMetadata {
        CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid,
            format: VCFormat::SdJwtVc,
            alg: None,
            fields: vec![],
        }
    }
    fn get_credential_metadata_sd_jwt_with_fields(kid: String) -> CredentialMetadata {
        CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid,
            format: VCFormat::SdJwtVc,
            alg: None,
            fields: vec![
                "$.vct".to_string(),
                "$.name".to_string(),
                "$.email.work".to_string(),
            ],
        }
    }

    async fn test_vault(vault: &AskarVault) {
        let cred1_id = store_sd_jwt_to_vault(vault).await;
        let cred2_id = store_ldp_vc_to_vault(vault).await;

        let get1_res = vault.get_credential(&cred1_id).await.unwrap().unwrap();
        let get2_res = vault.get_credential(&cred2_id).await.unwrap().unwrap();

        let expected_entry_sd_jwt = create_expected_entry_sd_jwt(get1_res.clone().id);
        let expected_entry_ldp_vc = create_expected_entry_ldp_vc(get2_res.clone().id);

        assert_eq!(
            serde_json::to_value(&get1_res).unwrap(),
            serde_json::to_value(expected_entry_sd_jwt.clone()).unwrap(),
        );
        assert_eq!(
            serde_json::to_value(&get2_res).unwrap(),
            serde_json::to_value(expected_entry_ldp_vc.clone()).unwrap(),
        );

        let get_all_res = vault.get_credentials(None).await.unwrap();

        let serde_json::Value::Array(get_all_values) = serde_json::to_value(&get_all_res).unwrap()
        else {
            panic!("failed to serialize credentials as json array");
        };

        assert!(
            get_all_values.contains(&serde_json::to_value(expected_entry_sd_jwt.clone()).unwrap())
        );
        assert!(
            get_all_values.contains(&serde_json::to_value(expected_entry_ldp_vc.clone()).unwrap())
        );

        let find_res = vault
            .find_credentials(
                vec![
                    "$.name".to_string(),
                    "$.email.work".to_string(),
                    "$.vct".to_string(),
                ],
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(find_res).unwrap(),
            serde_json::to_value(vec![expected_entry_sd_jwt.clone()]).unwrap()
        );

        vault.delete_credential(&cred1_id).await.unwrap();
        let get1_res = vault.get_credential(&cred1_id).await.unwrap();
        assert!(get1_res.is_none());
    }

    async fn create_test_vault() -> AskarVault {
        let storage = AskarStorage::create(
            &AskarStorageConfig {
                db_url: "sqlite://:memory:".to_owned(),
                key_method: KeyMethod::DeriveKey,
                pass_key: "1234".to_string(),
                profile: "test".to_string(),
            },
            false,
        )
        .await
        .unwrap();

        AskarVault::new(storage)
    }

    async fn store_sd_jwt_to_vault(vault: &AskarVault) -> String {
        let cred_meta = CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid: "1234".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            fields: vec![
                "$.vct".to_string(),
                "$.name".to_string(),
                "$.email.work".to_string(),
            ],
        };
        vault
            .store_credential(Credential::SdJwt(CRED_SD_JWT.to_string()), &cred_meta)
            .await
            .unwrap()
    }
    async fn store_ldp_vc_to_vault(vault: &AskarVault) -> String {
        let cred_meta = CredentialMetadata {
            type_: "VerifiableCredential".into(),
            kid: "1234".into(),
            format: VCFormat::LdpVc,
            alg: None,
            fields: vec![],
        };
        vault
            .store_credential(
                Credential::LdpVc(serde_json::from_str(CRED_LDP_VC).unwrap()),
                &cred_meta,
            )
            .await
            .unwrap()
    }

    fn create_expected_entry_sd_jwt(id: String) -> CredentialEntry {
        CredentialEntry {
            credential: Credential::SdJwt(CRED_SD_JWT.to_string()),
            kid: "1234".into(),
            id,
        }
    }
    fn create_expected_entry_ldp_vc(id: String) -> CredentialEntry {
        CredentialEntry {
            credential: Credential::LdpVc(serde_json::from_str(CRED_LDP_VC).unwrap()),
            kid: "1234".into(),
            id,
        }
    }

    async fn store_batch_of_credentials(vault: &AskarVault, amount: usize) {
        for i in 0..amount {
            vault
                .store_credential(
                    get_credential_sd_jwt().clone(),
                    &get_credential_metadata_sd_jwt_with_fields(i.to_string()),
                )
                .await
                .unwrap();
        }
    }
}
