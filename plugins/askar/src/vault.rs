use aries_askar::entry::{Entry, EntryKind, EntryTag, TagFilter};
use aries_askar::storage::backend::OrderBy;
use async_trait::async_trait;
use snafu::ensure;
use tracing::{instrument, Level};
use uuid::Uuid;

use crate::AskarStorage;
use agent_sdk::crypto::Alg;
use agent_sdk::vault::{
    DeletingSnafu, EmptyFieldsSnafu, Error, FormatNotSupportedSnafu, ResolvingSnafu, StoringSnafu,
    VCSnafu,
};
use agent_sdk::vc::{JWT_VC_JSON, JWT_VC_JSON_LD, LDP_VC, SD_JWT_VC};

pub use agent_sdk::vault::{CredentialEntry, Vault, VaultPagination};
pub use agent_sdk::vc::{Credential, CredentialMetadata, HasVCFormat, VCFormat};

pub const TAG_TYPE: &str = "type_";
pub const TAG_FORMAT: &str = "format";
pub const TAG_KID: &str = "kid";
pub const TAG_ALG: &str = "alg";

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
    use crate::vault::AskarVault;
    use crate::{AskarStorage, AskarStorageConfig, KeyMethod};
    use agent_sdk::vault::{CredentialEntry, Vault, VaultPagination};
    use agent_sdk::vc::{Credential, CredentialMetadata, VCFormat};
    use rstest::rstest;

    const CRED_SD_JWT: &str = "token";
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

    fn get_credential_sd_jwt() -> Credential {
        Credential::SdJwt("token".to_string())
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
}
