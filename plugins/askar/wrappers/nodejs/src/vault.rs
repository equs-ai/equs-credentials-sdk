use crate::kms::Alg;
use crate::AskarStorage;
use askar::vault::map_credential_fields_to_tags;
use askar::vault::{
    AskarVaultParamsSortBy, Credential, CredentialEntry, CredentialMetadata, HasVCFormat, VCFormat,
    Vault, VaultFetchOptions,
};
use napi::{Error, Result};
use napi_derive::napi;
use serde::{Deserialize, Serialize};

/// `Askar Vault`
///
/// An async `Vault` interface for managing Verifiable Credentials.
///
/// Should be implemented to be used with `Askar`.
///
/// Supports storing, retrieving, deleting, and finding {@link Credential}.
/// Supports closing {@link Vault}
///
/// @method storeCredential - {@link AskarVault.storeCredential}
/// @method deleteCredential - {@link AskarVault.deleteCredential}
/// @method getCredential - {@link AskarVault.getCredential}
/// @method getCredentials - {@link AskarVault.getCredentials}
/// @method findCredentials - {@link AskarVault.findCredentials}
/// @method closeVault - {@link AskarVault.closeVault}
#[napi]
pub struct AskarVault(askar::vault::AskarVault);

#[napi]
impl AskarVault {
    #[napi(constructor)]
    pub fn new(storage: &AskarStorage, profile: String) -> Self {
        let vault = askar::vault::AskarVault::new(&storage.0.clone(), profile);

        AskarVault(vault)
    }

    /// Stores the {@link Credential} in {@link Vault}.
    ///
    /// @param {Credential} credential - the {@link Credential} to store
    /// @param {CredentialMetadata} metadata - the corresponding {@link CredentialMetadata}
    ///
    /// @returns {string} An `ID` of the stored `credential` on success
    #[allow(private_interfaces)]
    #[napi]
    pub async fn store_credential(
        &self,
        #[napi(ts_arg_type = "Credential")] credential: InnerCredential,
        #[napi(ts_arg_type = "CredentialMetadata")] metadata: InnerCredentialMetadata,
    ) -> Result<String> {
        self.0
            .store_credential(credential.try_into()?, &metadata.into())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Get a {@link CredentialEntry} with {@link Credential} from {@link Vault}
    ///
    /// @param {string} id - `ID` of the stored {@link CredentialEntry}
    ///
    /// @returns {CredentialEntry | null}
    /// * {@link CredentialEntry} on success
    /// * `null` if no {@link CredentialEntry} was found by `id`
    #[allow(private_interfaces)]
    #[napi(ts_return_type = "Promise<CredentialEntry | null>")]
    pub async fn get_credential(&self, id: String) -> Result<Option<InnerCredentialEntry>> {
        let credential = self
            .0
            .get_credential(&id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        credential.map(|entry| entry.try_into()).transpose()
    }

    /// List all {@link CredentialEntry}s in {@link Vault}
    ///
    /// @returns {Array<CredentialEntry>}
    /// * An array of {@link CredentialEntry} on success
    /// * Empty array if there are no entries
    #[allow(private_interfaces)]
    #[napi(ts_return_type = "Promise<Array<CredentialEntry>>")]
    pub async fn get_credentials(
        &self,
        pagination: Option<InnerVaultPagination>,
    ) -> Result<Vec<InnerCredentialEntry>> {
        let credentials = self
            .0
            .get_credentials(pagination.map(From::from))
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        credentials
            .into_iter()
            .map(|entry| entry.try_into())
            .collect()
    }

    #[allow(private_interfaces)]
    #[napi(ts_return_type = "Promise<Array<CredentialEntry>>")]
    pub async fn get_with_options(
        &self,
        fields: Vec<String>,
        options: AskarVaultFetchOptions,
    ) -> Result<Vec<InnerCredentialEntry>> {
        let filter_tags = map_credential_fields_to_tags(fields);
        let credentials = self
            .0
            .get_with_options(filter_tags, options.into())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        credentials
            .into_iter()
            .map(|entry| entry.try_into())
            .collect()
    }

    /// Delete a {@link CredentialEntry} with {@link Credential} from {@link Vault}
    ///
    /// @param {string} id -  `ID` of the stored {@link CredentialEntry}
    ///
    /// @returns {void}
    #[napi]
    pub async fn delete_credential(&self, id: String) -> Result<()> {
        self.0
            .delete_credential(&id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Find the matching {@link CredentialEntry}s in {@link Vault}
    ///
    /// @param {Array<string>} fields -  an array of fields to search for credentials.
    ///
    /// @returns {Array<CredentialEntry>}
    /// * An array of {@link CredentialEntry} matched the provided `fields` on success
    /// * An empty array if nothing meets the `fields`
    #[allow(private_interfaces)]
    #[napi(ts_return_type = "Promise<Array<CredentialEntry>>")]
    pub async fn find_credentials(
        &self,
        fields: Vec<String>,
        pagination: Option<InnerVaultPagination>,
    ) -> Result<Vec<InnerCredentialEntry>> {
        let credentials = self
            .0
            .find_credentials(fields, pagination.map(From::from))
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        credentials
            .into_iter()
            .map(|entry| entry.try_into())
            .collect()
    }

    /// Counts all credentials in the vault, optionally filtered by category
    ///
    /// @param {string} category - Optional category to filter credentials by
    ///
    /// @returns {number} Total number of credentials matching the criteria
    /// * Returns total count of all credentials if no category specified
    /// * Returns count of credentials matching the category if specified
    #[napi]
    pub async fn count_all(&self, category: Option<String>) -> Result<u32> {
        let count = self
            .0
            .count_all(category)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(count as u32)
    }
}

#[napi]
#[derive(Debug, Serialize, Deserialize)]
pub enum InnerVCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
    MsoMdoc,
}

impl From<InnerVCFormat> for VCFormat {
    fn from(value: InnerVCFormat) -> Self {
        match value {
            InnerVCFormat::JwtVcJson => VCFormat::JwtVcJson,
            InnerVCFormat::JwtVcJsonLD => VCFormat::JwtVcJsonLD,
            InnerVCFormat::LdpVc => VCFormat::LdpVc,
            InnerVCFormat::SdJwtVc => VCFormat::SdJwtVc,
            InnerVCFormat::MsoMdoc => VCFormat::MsoMdoc,
        }
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
struct InnerCredential {
    pub format: InnerVCFormat,
    pub payload: String,
}

impl TryFrom<InnerCredential> for Credential {
    type Error = Error;

    fn try_from(value: InnerCredential) -> Result<Self> {
        let result = match value.format {
            InnerVCFormat::JwtVcJson => Self::JwtVcJson(value.payload),
            InnerVCFormat::JwtVcJsonLD => Self::JwtVcJsonLd(value.payload),
            InnerVCFormat::LdpVc => Self::LdpVc(serde_json::from_str(&value.payload)?),
            InnerVCFormat::SdJwtVc => Self::SdJwt(value.payload),
            _ => {
                return Err(Error::from_reason(
                    "Unsupported credential format: MSO MDOC",
                ))
            }
        };

        Ok(result)
    }
}

impl TryFrom<Credential> for InnerCredential {
    type Error = Error;

    fn try_from(value: Credential) -> Result<Self> {
        let result = match value {
            Credential::JwtVcJson(payload) => Self {
                format: InnerVCFormat::JwtVcJson,
                payload,
            },
            Credential::JwtVcJsonLd(payload) => Self {
                format: InnerVCFormat::JwtVcJsonLD,
                payload,
            },
            Credential::LdpVc(payload) => Self {
                format: InnerVCFormat::LdpVc,
                payload: serde_json::to_string(&payload)?,
            },
            Credential::SdJwt(payload) => Self {
                format: InnerVCFormat::SdJwtVc,
                payload,
            },
            _ => {
                return Err(Error::from_reason(format!(
                    "Unsupported credential format {}",
                    value.format()
                )))
            }
        };

        Ok(result)
    }
}
#[napi(object)]
struct InnerCredentialMetadata {
    pub type_: String,
    pub format: InnerVCFormat,
    pub kid: String,
    pub alg: Option<Alg>,
    pub fields: Vec<String>,
}

impl From<InnerCredentialMetadata> for CredentialMetadata {
    fn from(value: InnerCredentialMetadata) -> Self {
        Self {
            type_: value.type_,
            format: value.format.into(),
            kid: value.kid,
            alg: value.alg.map(|value| value.into()),
            fields: value.fields,
        }
    }
}

#[napi(object)]
struct InnerCredentialEntry {
    pub credential: InnerCredential,
    pub kid: String,
    pub id: String,
}

impl TryFrom<CredentialEntry> for InnerCredentialEntry {
    type Error = Error;

    fn try_from(value: CredentialEntry) -> Result<Self> {
        Ok(InnerCredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

/// An interface for pagination in Vault
///
/// @property {offset} offset - amount of items to skip
/// @property {limit} limit - maximum amount of items to get
#[napi(object)]
struct InnerVaultPagination {
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl From<InnerVaultPagination> for VaultFetchOptions {
    fn from(value: InnerVaultPagination) -> Self {
        Self {
            offset: value.offset.map(|value| value as usize),
            limit: value.limit.map(|value| value as usize),
        }
    }
}
impl From<VaultFetchOptions> for InnerVaultPagination {
    fn from(value: VaultFetchOptions) -> Self {
        Self {
            offset: value.offset.map(|value| value as u32),
            limit: value.limit.map(|value| value as u32),
        }
    }
}

#[napi(object)]
struct AskarVaultFetchOptions {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort_by: Option<AskarVaultSortBy>,
    pub sort_order: Option<AskarVaultParamsSortOrder>,
}

impl From<AskarVaultFetchOptions> for askar::vault::AskarVaultFetchOptions {
    fn from(value: AskarVaultFetchOptions) -> Self {
        Self {
            offset: value.offset.map(|v| v as i64),
            limit: value.limit.map(|v| v as i64),
            sort_by: value.sort_by.map(From::from),
            sort_order: value.sort_order.map(From::from),
        }
    }
}

#[napi]
#[derive(Debug, Serialize, Deserialize)]
pub enum AskarVaultSortBy {
    Id,
}

impl From<AskarVaultSortBy> for AskarVaultParamsSortBy {
    fn from(value: AskarVaultSortBy) -> Self {
        match value {
            AskarVaultSortBy::Id => AskarVaultParamsSortBy::Id,
        }
    }
}

#[napi]
#[derive(Debug, Serialize, Deserialize)]
pub enum AskarVaultParamsSortOrder {
    Ascending,
    Descending,
}

impl From<AskarVaultParamsSortOrder> for askar::vault::AskarVaultParamsSortOrder {
    fn from(value: AskarVaultParamsSortOrder) -> Self {
        match value {
            AskarVaultParamsSortOrder::Ascending => {
                askar::vault::AskarVaultParamsSortOrder::Ascending
            }
            AskarVaultParamsSortOrder::Descending => {
                askar::vault::AskarVaultParamsSortOrder::Descending
            }
        }
    }
}
