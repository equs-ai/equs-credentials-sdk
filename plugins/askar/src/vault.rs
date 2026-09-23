use aries_askar::Session;
use aries_askar::entry::{Entry, EntryKind, EntryTag, TagFilter};
use aries_askar::storage::backend::OrderBy;
use async_trait::async_trait;
use snafu::ensure;
use tracing::{Level, instrument};
use uuid::Uuid;

use crate::AskarStorage;
use equs_sdk::crypto::Alg;
use equs_sdk::vault::{
    ConversionToEntrySnafu, DeletingSnafu, EmptyFieldsSnafu, Error, FetchingSnafu,
    FormatNotSupportedSnafu, ResolvingSnafu, SessionSnafu, StoringSnafu, VCSnafu,
};
use equs_sdk::vc::{JWT_VC_JSON, JWT_VC_JSON_LD, LDP_VC, SD_JWT_VC};

pub use equs_sdk::vault::{CredentialEntry, Vault, VaultFetchOptions};
pub use equs_sdk::vc::{Credential, CredentialMetadata, HasVCFormat, VCFormat};

pub const TAG_TYPE: &str = "type_";
pub const TAG_FORMAT: &str = "format";
pub const TAG_KID: &str = "kid";
pub const TAG_ALG: &str = "alg";

#[derive(Debug)]
pub struct AskarVaultFetchOptions {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub sort_by: Option<AskarVaultParamsSortBy>,
    pub sort_order: Option<AskarVaultParamsSortOrder>,
}

impl TryFrom<VaultFetchOptions> for AskarVaultFetchOptions {
    type Error = Error;
    fn try_from(options: VaultFetchOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            offset: options.offset.map(|value| value as i64),
            limit: options.limit.map(|value| value as i64),
            sort_by: None,
            sort_order: None,
        })
    }
}

pub type AskarVaultParamsSortBy = OrderBy;

#[derive(Debug, Default)]
pub enum AskarVaultParamsSortOrder {
    #[default]
    Ascending,
    Descending,
}

impl AskarVaultParamsSortOrder {
    pub fn is_descending(&self) -> bool {
        matches!(self, AskarVaultParamsSortOrder::Descending)
    }
}

#[derive(Debug, Clone)]
pub struct AskarVault {
    storage: AskarStorage,
    profile: String,
}

impl AskarVault {
    async fn session(&self) -> Result<Session, aries_askar::Error> {
        self.storage.session(Some(self.profile.clone())).await
    }
}

impl AskarVault {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new(storage: &AskarStorage, profile: String) -> Self {
        Self {
            storage: storage.to_owned(),
            profile,
        }
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    pub async fn get_with_options(
        &self,
        filter: Option<TagFilter>,
        options: AskarVaultFetchOptions,
    ) -> Result<Vec<CredentialEntry>, Error> {
        let entries = self
            .session()
            .await
            .map_err(|e| {
                SessionSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .fetch_all(
                None,
                filter,
                options.offset,
                options.limit,
                options.sort_by,
                options.sort_order.unwrap_or_default().is_descending(),
                false,
            )
            .await
            .map_err(|e| {
                FetchingSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        let mut result = vec![];

        for entry in entries {
            let credential = entry_to_credential(entry).map_err(|e| {
                ConversionToEntrySnafu {
                    details: e.to_string(),
                }
                .build()
            })?;
            result.push(credential);
        }

        Ok(result)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn insert(&self, entity: &Entry) -> Result<AskarVaultId, aries_askar::Error> {
        let mut session = self.session().await?;

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
        let mut session = self.session().await?;
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
        let mut session = self.session().await?;
        session.fetch(id.category(), id.name(), false).await
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn get_all(&self) -> Result<Vec<Entry>, aries_askar::Error> {
        let mut session = self.session().await?;
        session
            .fetch_all(None, None, None, None, Some(OrderBy::Id), false, false)
            .await
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn find(&self, filter: TagFilter) -> Result<Vec<Entry>, aries_askar::Error> {
        let mut session = self.session().await?;
        session
            .fetch_all(None, Some(filter), None, None, None, false, false)
            .await
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

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    pub async fn count_all(&self, category: Option<String>) -> Result<i64, aries_askar::Error> {
        let mut session = self.session().await?;
        session.count(category.as_deref(), None).await
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
        options: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>, Error> {
        if let Some(options) = options {
            self.get_with_options(None, options.try_into()?).await
        } else {
            let entries = self.get_all().await.map_err(|err| {
                FetchingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;
            entries.into_iter().map(entry_to_credential).collect()
        }
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
        options: Option<VaultFetchOptions>,
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

        if let Some(options) = options {
            self.to_owned()
                .get_with_options(Some(tag_filter), options.try_into()?)
                .await
        } else {
            let entries = self.find(tag_filter).await.map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;
            entries.into_iter().map(entry_to_credential).collect()
        }
    }
}

#[derive(Debug)]
struct AskarVaultId(String, String);

impl AskarVaultId {
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
    type Error = equs_sdk::vault::Error;

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
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

#[instrument(level = Level::TRACE, ret())]
pub fn map_credential_fields_to_tags(fields: Vec<String>) -> Option<TagFilter> {
    // TODO we use exist but it requires Vec<String>. A bit confusing. Search for better solution
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
        AskarVault, AskarVaultFetchOptions, AskarVaultParamsSortBy, AskarVaultParamsSortOrder,
    };
    use crate::{AskarStorage, AskarStorageConfig, KeyMethod};
    use equs_sdk::vault::{CredentialEntry, Vault, VaultFetchOptions};
    use equs_sdk::vc::{Credential, CredentialMetadata, VCFormat};
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

        // vault.close_vault().await.unwrap();
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
    async fn multiple_vaults_using_same_storage() {
        let storage = create_test_storage().await;

        let profile_1 = "test_profile_1".to_string();
        let profile_2 = "test_profile_2".to_string();
        let profile_3 = "test_profile_3".to_string();
        let profile_4 = "test_profile_4".to_string();

        storage.ensure_profile(profile_1.clone()).await.unwrap();
        storage.ensure_profile(profile_2.clone()).await.unwrap();
        storage.ensure_profile(profile_3.clone()).await.unwrap();
        storage.ensure_profile(profile_4.clone()).await.unwrap();

        let vault_1 = AskarVault::new(&storage, profile_1.clone());
        let vault_2 = AskarVault::new(&storage, profile_2.clone());
        let vault_3 = AskarVault::new(&storage, profile_3.clone());
        let vault_4 = AskarVault::new(&storage, profile_4.clone());

        let sd_jwt_cred_id_1 = store_sd_jwt_to_vault(&vault_1).await;
        let sd_jwt_cred_id_2 = store_sd_jwt_to_vault(&vault_2).await;
        let sd_jwt_cred_id_3 = store_sd_jwt_to_vault(&vault_3).await;
        let sd_jwt_cred_id_4 = store_sd_jwt_to_vault(&vault_4).await;

        vault_1
            .get_credential(&sd_jwt_cred_id_1.clone())
            .await
            .unwrap()
            .unwrap();
        vault_2
            .get_credential(&sd_jwt_cred_id_2.clone())
            .await
            .unwrap()
            .unwrap();
        vault_3
            .get_credential(&sd_jwt_cred_id_3.clone())
            .await
            .unwrap()
            .unwrap();
        vault_4
            .get_credential(&sd_jwt_cred_id_4.clone())
            .await
            .unwrap()
            .unwrap();

        storage.remove_profile(profile_1.clone()).await.unwrap();
        storage.remove_profile(profile_2.clone()).await.unwrap();

        let _ = vault_1
            .get_credential(&sd_jwt_cred_id_1.clone())
            .await
            .map_err(|e| {
                assert_eq!(
                    e.to_string(),
                    "Credential resolving error: Profile not found".to_string()
                )
            });
        let _ = vault_2
            .get_credential(&sd_jwt_cred_id_2.clone())
            .await
            .map_err(|e| {
                assert_eq!(
                    e.to_string(),
                    "Credential resolving error: Profile not found".to_string()
                )
            });
        vault_3
            .get_credential(&sd_jwt_cred_id_3.clone())
            .await
            .unwrap()
            .unwrap();
        vault_4
            .get_credential(&sd_jwt_cred_id_4.clone())
            .await
            .unwrap()
            .unwrap();
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
    #[case(0, 5, 5)]
    #[case(0, 10, 10)]
    #[case(10, 11, 0)]
    #[case(3, 3, 3)]
    #[case(8, 3, 2)]
    #[tokio::test]
    async fn get_credentials_with_pagination_succeed(
        #[case] offset: usize,
        #[case] limit: usize,
        #[case] amount_to_get_from_vault: usize,
    ) {
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
        let credentials = vault
            .get_credentials(Some(VaultFetchOptions {
                offset: Some(offset),
                limit: Some(limit),
            }))
            .await
            .unwrap();

        assert_eq!(credentials.len(), amount_to_get_from_vault);
    }
    #[rstest]
    #[case(0, 5, 5)]
    #[case(0, 10, 10)]
    #[case(10, 11, 0)]
    #[case(3, 3, 3)]
    #[case(8, 3, 2)]
    #[tokio::test]
    async fn get_credentials_with_options_succeed(
        #[case] offset: usize,
        #[case] limit: usize,
        #[case] amount_to_get_from_vault: usize,
    ) {
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
        let credentials = vault
            .get_with_options(
                None,
                AskarVaultFetchOptions {
                    offset: Some(offset as i64),
                    limit: Some(limit as i64),
                    sort_by: Some(AskarVaultParamsSortBy::Id),
                    sort_order: Some(AskarVaultParamsSortOrder::Ascending),
                },
            )
            .await
            .unwrap();

        assert_eq!(credentials.len(), amount_to_get_from_vault);
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
    #[case(vec!["$.vct".to_string()], 0, 10, 10)]
    #[case(vec!["$.vct".to_string()], 0, 11, 10)]
    #[case(vec!["$.vct".to_string()], 2, 10, 8)]
    #[case(vec!["$.fake".to_string()], 0, 5, 0)]
    #[case(vec!["$.vct".to_string()], 3, 3, 3)]
    #[case(vec!["$.vct".to_string()], 8, 3, 2)]
    #[tokio::test]
    async fn find_credentials_with_pagination_succeeds(
        #[case] fields: Vec<String>,
        #[case] offset: usize,
        #[case] limit: usize,
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

    async fn create_test_storage() -> AskarStorage {
        AskarStorage::create(
            &AskarStorageConfig {
                db_url: "sqlite://:memory:".to_owned(),
                key_method: KeyMethod::DeriveKey,
                pass_key: "1234".to_string(),
                profile: "test".to_string(),
            },
            false,
        )
        .await
        .unwrap()
    }

    async fn create_test_vault() -> AskarVault {
        let storage = create_test_storage().await;
        let profile = "test_profile".to_string();

        storage.ensure_profile(profile.clone()).await.unwrap();
        AskarVault::new(&storage, profile)
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
}
