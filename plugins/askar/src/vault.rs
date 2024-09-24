use aries_askar::entry::{Entry, EntryKind, EntryTag, TagFilter};
use aries_askar::Store;
use async_trait::async_trait;
use snafu::ensure;
use tracing::{instrument, Level};
use uuid::Uuid;

use agent_sdk::crypto::Alg;
use agent_sdk::vault::{
    CredentialEntry, Error, FindCriteria, FormatNotSupportedSnafu, ResolvingSnafu, StoringSnafu,
    VCSnafu, Vault,
};
use agent_sdk::vc::{
    Credential, CredentialMetadata, VCFormat, JWT_VC_JSON, JWT_VC_JSON_LD, LDP_VC, SD_JWT_VC,
};

pub const TAG_TYPE: &str = "type_";
pub const TAG_FORMAT: &str = "format";
pub const TAG_KID: &str = "kid";
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
            EntryTag::Encrypted(TAG_KID.to_string(), metadata.kid.to_owned()),
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
    async fn get_credential(&self, id: &str) -> Result<Option<CredentialEntry>, Error> {
        let entry = self.get(id.try_into()?).await.map_err(|err| {
            StoringSnafu {
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
        ret(level = Level::TRACE)
    )]
    async fn find_credentials(
        &self,
        criteria: FindCriteria,
    ) -> Result<Vec<CredentialEntry>, Error> {
        let tag_filter = find_criteria_to_tag_filter(criteria);

        if tag_filter.is_none() {
            return StoringSnafu {
                details: "empty tag filter",
            }
            .fail();
        }

        let entries = self.find(tag_filter.unwrap()).await.map_err(|err| {
            StoringSnafu {
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

fn find_criteria_to_tag_filter(criteria: FindCriteria) -> Option<TagFilter> {
    match criteria {
        FindCriteria::ByTypeAndFormat(type_, format) => Some(TagFilter::all_of(vec![
            TagFilter::is_eq(TAG_TYPE, type_),
            TagFilter::is_eq(TAG_FORMAT, format),
        ])),
        _ => None,
    }
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
            let credential =
                ssi::vc::Credential::from_json_unsigned(&credential_str).map_err(|err| {
                    VCSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;
            Credential::LdpVc(credential)
        }
        SD_JWT_VC => Credential::SdJwt(credential_str),
        _ => FormatNotSupportedSnafu {
            format: entry.category,
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

    Ok(CredentialEntry { credential, kid })
}

#[cfg(test)]
mod tests {
    use crate::AskarStorage;
    use agent_sdk::vault::{CredentialEntry, FindCriteria, Vault};
    use agent_sdk::vc::{Credential, CredentialMetadata, VCFormat};

    // TODO: consider splitting this test into several small unit tests
    #[tokio::test]
    async fn test_askar_vault() {
        let storage = AskarStorage::create("sEcrEt", Some("Askar-Wallet".to_string()))
            .await
            .unwrap();
        let vault = storage.vault();
        test_vault(vault).await;
        storage.close().await.unwrap();
    }

    pub async fn test_vault<V: Vault>(vault: V) {
        // test data
        let cred1 = "token".to_string();
        let cred1_meta = CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid: "1234".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            tags: vec![],
        };
        let cred2str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let cred2: ssi::vc::Credential = serde_json::from_str(cred2str).unwrap();
        let cred2_meta = CredentialMetadata {
            type_: "VerifiableCredential".into(),
            kid: "1234".into(),
            format: VCFormat::LdpVc,
            alg: None,
            tags: vec![],
        };

        let cred1_id = vault
            .store_credential(Credential::SdJwt(cred1.clone()), &cred1_meta)
            .await
            .unwrap();
        let cred2_id = vault
            .store_credential(Credential::LdpVc(cred2.clone()), &cred2_meta)
            .await
            .unwrap();

        let get1_res = vault.get_credential(&cred1_id).await.unwrap();
        let get2_res = vault.get_credential(&cred2_id).await.unwrap();

        assert_eq!(
            get1_res,
            Some(CredentialEntry {
                credential: Credential::SdJwt(cred1.clone()),
                kid: "1234".into()
            }),
        );
        assert_eq!(
            get2_res,
            Some(CredentialEntry {
                credential: Credential::LdpVc(cred2.clone()),
                kid: "1234".into()
            }),
        );

        let find_res = vault
            .find_credentials(FindCriteria::ByTypeAndFormat(
                "https://credentials.example.com/identity_credential".to_owned(),
                VCFormat::SdJwtVc.to_string(),
            ))
            .await
            .unwrap();

        assert_eq!(
            find_res,
            vec![CredentialEntry {
                credential: Credential::SdJwt(cred1),
                kid: "1234".into()
            }]
        );
    }
}
