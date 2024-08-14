use crate::core_::crypto::Alg;
use crate::core_::vault::{Error, FindCriteria, Vault};
use crate::core_::vc;
use crate::core_::vc::{
    ldp_vc, Credential, CredentialMetadata, VCFormat, JWT_VC_JSON, JWT_VC_JSON_LD, LDP_VC,
    SD_JWT_VC,
};
use aries_askar::entry::{Entry, EntryKind, EntryTag, TagFilter};
use aries_askar::Store;
use async_trait::async_trait;
use uuid::Uuid;

pub const TAG_ID: &str = "id";
pub const TAG_FORMAT: &str = "format";
pub const TAG_ALG: &str = "alg";

pub struct AskarVault(Store);

impl AskarVault {
    pub(super) fn new(store: Store) -> Self {
        AskarVault(store)
    }

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

        Ok(AskarVaultId(entity.category.to_owned(), entity.name.to_owned()))
    }

    async fn get(&self, id: AskarVaultId) -> Result<Option<Entry>, aries_askar::Error> {
        let mut seesion = self.0.session(None).await?;
        seesion.fetch(id.category(), id.name(), false).await
    }

    async fn find(&self, filter: TagFilter) -> Result<Vec<Entry>, aries_askar::Error> {
        let mut session = self.0.session(None).await?;
        session.fetch_all(None, Some(filter), None, false).await
    }

    fn create_entry(
        credential: &Credential,
        metadata: &CredentialMetadata,
    ) -> Result<Entry, vc::Error> {
        let name = Uuid::new_v4().to_string();
        let tags = vec![
            EntryTag::Encrypted(TAG_ID.to_string(), metadata.id.to_owned()),
            EntryTag::Encrypted(
                TAG_FORMAT.to_string(),
                <&VCFormat as Into<&str>>::into(&metadata.format).to_string(),
            ),
            EntryTag::Encrypted(
                TAG_ALG.to_string(),
                <Alg as Into<&str>>::into(metadata.alg).to_string(),
            ),
        ];

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
                let credential_json = serde_json::to_string(&credential)
                    .map_err(|err| vc::Error::Parsing(err.to_string()))?;
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
    async fn store_credential(
        &mut self,
        credential: Credential,
        metadata: &CredentialMetadata,
    ) -> Result<String, Error> {
        let entry = Self::create_entry(&credential, &metadata)?;
        let id = self.insert(&entry)
            .await
            .map_err(|err| Error::Storage(err.to_string()))?;

        Ok(id.into())
    }

    async fn get_credential(&self, id: &str) -> Result<Credential, Error> {
        let entry = self
            .get(id.try_into()?)
            .await
            .map_err(|err| Error::Storage(err.to_string()))?
            .ok_or_else(|| Error::NotFound(id.to_string()))?;

        entry.try_into()
    }

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<Credential>, Error> {
        let entries = self
            .find(criteria.into())
            .await
            .map_err(|err| Error::Storage(err.to_string()))?;
        entries.into_iter().map(|entry| entry.try_into()).collect()
    }
}

struct AskarVaultId(String, String);

impl AskarVaultId {
    pub fn new(category: String, name: String) -> Self {
        AskarVaultId(category, name)
    }

    pub fn category(&self) -> &str {
        &self.0
    }

    pub fn name(&self) -> &str {
        &self.1
    }
}

impl TryFrom<&str> for AskarVaultId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts = value.split(":").collect::<Vec<&str>>();

        if parts.len() != 2 {
            return Err(Error::Storage(format!("Incorrect ID: {}", value)));
        }

        let category = parts[0].to_string();
        let name = parts[1].to_string();

        Ok(AskarVaultId(category, name))
    }
}

impl From<AskarVaultId> for String {
    fn from(value: AskarVaultId) -> Self {
        format!("{}:{}", value.0, value.1)
    }
}

impl From<FindCriteria> for TagFilter {
    fn from(value: FindCriteria) -> Self {
        match value {
            FindCriteria::ByIdAndFormat(id, format) => TagFilter::all_of(vec![
                TagFilter::is_eq(TAG_ID, id),
                TagFilter::is_eq(
                    TAG_FORMAT,
                    <&VCFormat as Into<&str>>::into(&format).to_string(),
                ),
            ]),
        }
    }
}

impl TryFrom<Entry> for Credential {
    type Error = Error;

    fn try_from(value: Entry) -> Result<Self, Self::Error> {
        let credential_str = value
            .value
            .as_opt_str()
            .ok_or_else(|| {
                vc::Error::Parsing("Failed to convert secret bytes to credential string".to_string())
            })?
            .to_string();

        match value.category.as_str() {
            JWT_VC_JSON => Ok(Credential::JwtVcJson(credential_str)),
            JWT_VC_JSON_LD => Ok(Credential::JwtVcJsonLd(credential_str)),
            LDP_VC => {
                let credential = ldp_vc::Credential::from_json_unsigned(&credential_str)
                    .map_err(|err| vc::Error::Parsing(err.to_string()))?;
                Ok(Credential::LdpVc(credential))
            }
            SD_JWT_VC => Ok(Credential::SdJwt(credential_str)),
            _ => Err(Error::VC(vc::Error::FormatNotSupported)),
        }
    }
}
