use aries_askar::entry::{Entry, EntryKind, EntryTag, TagFilter};
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

pub use agent_sdk::vault::{CredentialEntry, Vault};
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
            .fetch_all(None, None, None, None, false, false)
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
    async fn get_credentials(&self) -> Result<Vec<CredentialEntry>, Error> {
        let entries = self.get_all().await.map_err(|err| {
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
    async fn find_credentials(&self, fields: Vec<String>) -> Result<Vec<CredentialEntry>, Error> {
        if fields.is_empty() {
            EmptyFieldsSnafu.fail()?
        };
        let tag_filter = map_credential_fields_to_tags(fields).ok_or_else(|| {
            ResolvingSnafu {
                details: "empty tag filter",
            }
            .build()
        })?;

        let entries = self.find(tag_filter).await.map_err(|err| {
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
    let tags = vec![TagFilter::exist(fields)];

    if tags.is_empty() {
        return None;
    }

    Some(TagFilter::all_of(tags))
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
    use agent_sdk::vault::{CredentialEntry, Vault};
    use agent_sdk::vc::{Credential, CredentialMetadata, VCFormat};

    // TODO: consider splitting this test into several small unit tests
    #[tokio::test]
    async fn test_askar_vault() {
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

        let vault = AskarVault::new(storage);
        test_vault(&vault).await;

        vault.close_vault().await.unwrap();
    }

    pub async fn test_vault<V: Vault>(vault: &V) {
        // test data
        let cred1 = "token".to_string();
        let cred1_meta = CredentialMetadata {
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
        let cred2 = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let cred2_meta = CredentialMetadata {
            type_: "VerifiableCredential".into(),
            kid: "1234".into(),
            format: VCFormat::LdpVc,
            alg: None,
            fields: vec![],
        };

        let cred1_id = vault
            .store_credential(Credential::SdJwt(cred1.clone()), &cred1_meta)
            .await
            .unwrap();
        let cred2_id = vault
            .store_credential(
                Credential::LdpVc(serde_json::from_str(cred2).unwrap()),
                &cred2_meta,
            )
            .await
            .unwrap();

        let get1_res = vault.get_credential(&cred1_id).await.unwrap().unwrap();
        let get2_res = vault.get_credential(&cred2_id).await.unwrap().unwrap();

        assert_eq!(
            serde_json::to_value(&get1_res).unwrap(),
            serde_json::to_value(CredentialEntry {
                credential: Credential::SdJwt(cred1.clone()),
                kid: "1234".into(),
                id: get1_res.clone().id
            })
            .unwrap(),
        );
        assert_eq!(
            serde_json::to_value(&get2_res).unwrap(),
            serde_json::to_value(CredentialEntry {
                credential: Credential::LdpVc(serde_json::from_str(cred2).unwrap()),
                kid: "1234".into(),
                id: get2_res.clone().id
            })
            .unwrap(),
        );

        let get_all_res = vault.get_credentials().await.unwrap();

        let serde_json::Value::Array(get_all_values) = serde_json::to_value(&get_all_res).unwrap()
        else {
            panic!("failed to serialize credentials as json array");
        };

        let expected_entry_sd_jwt = CredentialEntry {
            credential: Credential::SdJwt(cred1.clone()),
            kid: "1234".into(),
            id: get1_res.clone().id,
        };

        let expected_entry_ldp_vc = CredentialEntry {
            credential: Credential::LdpVc(serde_json::from_str(cred2).unwrap()),
            kid: "1234".into(),
            id: get2_res.id,
        };

        assert!(get_all_values.contains(&serde_json::to_value(expected_entry_sd_jwt).unwrap()));
        assert!(get_all_values.contains(&serde_json::to_value(expected_entry_ldp_vc).unwrap()));

        let find_res = vault
            .find_credentials(vec![
                "$.name".to_string(),
                "$.email.work".to_string(),
                "$.vct".to_string(),
            ])
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(find_res).unwrap(),
            serde_json::to_value(vec![CredentialEntry {
                credential: Credential::SdJwt(cred1),
                kid: "1234".into(),
                id: get1_res.id
            }])
            .unwrap()
        );

        vault.delete_credential(&cred1_id).await.unwrap();
        let get1_res = vault.get_credential(&cred1_id).await.unwrap();
        assert!(get1_res.is_none());
    }
}
