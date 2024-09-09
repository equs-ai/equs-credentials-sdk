use aries_askar::entry::{Entry, EntryKind, EntryTag, TagFilter};
use aries_askar::Store;
use async_trait::async_trait;
use snafu::ensure;
use tracing::{instrument, Level};
use uuid::Uuid;

use crate::crypto::Alg;
use crate::vault::{
    Error, FindCriteria, FormatNotSupportedSnafu, ResolvingSnafu, StoringSnafu, VCSnafu, Vault,
};
use crate::vc::{
    Credential, CredentialMetadata, VCFormat, JWT_VC_JSON, JWT_VC_JSON_LD, LDP_VC, SD_JWT_VC,
};

pub const TAG_TYPE: &str = "type_";
pub const TAG_FORMAT: &str = "format";
pub const TAG_ALG: &str = "alg";

#[derive(Debug)]
pub struct AskarVault(Store);

impl AskarVault {
    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE)
    )]
    pub(super) fn new(store: Store) -> Self {
        AskarVault(store)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn insert(&self, entity: &Entry) -> Result<AskarVaultId, aries_askar::Error> {
        let mut session = self.0.session(None).await?;
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
        ret(level = Level::TRACE)
    )]
    async fn get(&self, id: AskarVaultId) -> Result<Option<Entry>, aries_askar::Error> {
        let mut seesion = self.0.session(None).await?;
        seesion.fetch(id.category(), id.name(), false).await
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn find(&self, filter: TagFilter) -> Result<Vec<Entry>, aries_askar::Error> {
        let mut session = self.0.session(None).await?;
        session.fetch_all(None, Some(filter), None, false).await
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE)
    )]
    fn create_entry(
        credential: &Credential,
        metadata: &CredentialMetadata,
    ) -> Result<Entry, Error> {
        let name = Uuid::new_v4().to_string();
        let mut tags = vec![
            EntryTag::Encrypted(TAG_TYPE.to_string(), metadata.type_.to_owned()),
            EntryTag::Encrypted(
                TAG_FORMAT.to_string(),
                <&VCFormat as Into<&str>>::into(&metadata.format).to_string(),
            ),
        ];

        if let Some(alg) = metadata.alg {
            tags.push(EntryTag::Encrypted(
                TAG_ALG.to_string(),
                <Alg as Into<&str>>::into(alg).to_string(),
            ))
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
        }
    }
}

#[async_trait]
impl Vault for AskarVault {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
    )]
    async fn get_credential(&self, id: &str) -> Result<Option<Credential>, Error> {
        let entry = self.get(id.try_into()?).await.map_err(|err| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        entry.map(|en| en.try_into()).transpose()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<Credential>, Error> {
        let entries = self.find(criteria.into()).await.map_err(|err| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })?;
        entries.into_iter().map(|entry| entry.try_into()).collect()
    }
}

#[derive(Debug)]
struct AskarVaultId(String, String);

impl AskarVaultId {
    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE)
    )]
    pub fn new(category: String, name: String) -> Self {
        AskarVaultId(category, name)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(level = Level::TRACE)
    )]
    pub fn category(&self) -> &str {
        &self.0
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
    )]
    fn from(value: AskarVaultId) -> Self {
        format!("{}:{}", value.0, value.1)
    }
}

impl From<FindCriteria> for TagFilter {
    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE)
    )]
    fn from(value: FindCriteria) -> Self {
        match value {
            FindCriteria::ByTypeAndFormat(type_, format) => TagFilter::all_of(vec![
                TagFilter::is_eq(TAG_TYPE, type_),
                TagFilter::is_eq(TAG_FORMAT, format),
            ]),
        }
    }
}

impl TryFrom<Entry> for Credential {
    type Error = Error;

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE)
    )]
    fn try_from(value: Entry) -> Result<Self, Self::Error> {
        let credential_str = value
            .value
            .as_opt_str()
            .ok_or_else(|| {
                VCSnafu {
                    details: "Failed to convert secret bytes to credential string",
                }
                .build()
            })?
            .to_string();

        match value.category.as_str() {
            JWT_VC_JSON => Ok(Credential::JwtVcJson(credential_str)),
            JWT_VC_JSON_LD => Ok(Credential::JwtVcJsonLd(credential_str)),
            LDP_VC => {
                let credential =
                    ssi::vc::Credential::from_json_unsigned(&credential_str).map_err(|err| {
                        VCSnafu {
                            details: err.to_string(),
                        }
                        .build()
                    })?;
                Ok(Credential::LdpVc(credential))
            }
            SD_JWT_VC => Ok(Credential::SdJwt(credential_str)),
            _ => FormatNotSupportedSnafu {
                format: value.category,
            }
            .fail(),
        }
    }
}
