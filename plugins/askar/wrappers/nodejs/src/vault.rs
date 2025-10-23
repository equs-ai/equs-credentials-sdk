use crate::kms::Alg;
use crate::AskarStorage;
use askar::vault::{
    AskarVaultCursorParamsOrderBy, Credential, CredentialEntry, CredentialMetadata, HasVCFormat,
    VCFormat, Vault, VaultPagination,
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
    pub fn new(storage: &AskarStorage) -> Self {
        let storage = storage.clone();
        let vault = askar::vault::AskarVault::new(storage.0.clone());

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

    /// Closes the connection to the {@link Vault}
    ///
    /// @returns {void}
    #[allow(clippy::missing_safety_doc)]
    #[napi]
    pub async unsafe fn close_vault(&mut self) -> Result<()> {
        self.0
            .to_owned()
            .close_vault()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(())
    }

    /// Creates a cursor for efficiently scanning through credentials in the vault.
    ///
    /// The cursor allows iterating through large sets of credentials in batches,
    /// providing memory-efficient access to the data. Each batch is fetched only when
    /// needed using the `fetch_next()` method.
    ///
    /// @param {AskarVaultCursorParams} params - Parameters for cursor configuration:
    /// * `batch_size`: Number of entries to fetch in each batch. If not provided the default value is 32
    /// * `fields`: Array of fields to filter credentials
    /// * `limit`: Optional maximum number of entries to return in total
    /// * `offset`: Optional number of entries to skip before starting
    /// * `order_by`: Optional parameter to specify ordering (e.g., by ID)
    /// * `sort_by`: Optional parameter to specify a sort direction (Ascending/Descending)
    ///
    /// @returns {AskarVaultCursor} Cursor object that can be used to iterate through credentials
    /// using `fetch_next()` method which returns batches of credentials until exhausted
    #[allow(private_interfaces)]
    #[napi]
    pub async fn create_cursor(&self, params: AskarVaultCursorParams) -> Result<AskarVaultCursor> {
        let cursor = self
            .0
            .create_cursor(params.into())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(AskarVaultCursor(cursor))
    }

    /// Counts all credentials in the vault, optionally filtered by category
    ///
    /// @param {string} category - Optional category to filter credentials by
    ///
    /// @returns {number} Total number of credentials matching the criteria
    /// * Returns total count of all credentials if no category specified
    /// * Returns count of credentials matching the category if specified
    #[allow(private_interfaces)]
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

/// An interface for pagination in Vault. `page` * `batchSize` - number of elements to skip and then takes `batchSize` number of elements
///
/// @property {page} page - page index
/// @property {batchSize} batchSize - size of batch to get
#[napi(object)]
struct InnerVaultPagination {
    pub page: u32,
    pub batch_size: u32,
}

impl From<InnerVaultPagination> for VaultPagination {
    fn from(value: InnerVaultPagination) -> Self {
        Self::new(value.page as usize, value.batch_size as usize)
    }
}
impl From<VaultPagination> for InnerVaultPagination {
    fn from(value: VaultPagination) -> Self {
        Self {
            page: value.page as u32,
            batch_size: value.batch_size as u32,
        }
    }
}

#[napi(object)]
struct AskarVaultCursorParams {
    pub fields: Vec<String>,
    pub batch_size: Option<u32>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub order_by: Option<AskarVaultCursorOrderBy>,
    pub sort_by: Option<AskarVaultCursorSortBy>,
}

#[napi]
#[derive(Debug, Serialize, Deserialize)]
pub enum AskarVaultCursorOrderBy {
    Id,
}

#[napi]
#[derive(Debug, Serialize, Deserialize)]
pub enum AskarVaultCursorSortBy {
    Ascending,
    Descending,
}

#[napi]
pub struct AskarVaultCursor(askar::vault::AskarVaultCursor<'static>);

#[napi]
impl AskarVaultCursor {
    /// Fetches the next batch of credentials based on cursor configuration
    ///
    /// Returns credentials in batches according to the batch_size specified when creating the cursor.
    /// Each call returns the next batch until all matching credentials have been returned.
    ///
    /// # Note
    /// Aries Askar library has a 32-element restriction for single batch fetch.
    /// The inner implementation makes extra inner fetch calls to fill the batch size when it is greater than 32.
    /// And remaining entries will be persistent in runtime and will be used for future calls of this method.
    ///
    /// @returns {Array<CredentialEntry> | null}
    /// * An array of {@link CredentialEntry} containing up to batch_size credentials
    /// * `null` if no more credentials match the cursor criteria
    /// * Throws error if fetching fails
    #[allow(private_interfaces)]
    #[napi(ts_return_type = "Promise<Array<CredentialEntry> | null>")]
    pub async unsafe fn fetch_next(&mut self) -> Result<Option<Vec<InnerCredentialEntry>>> {
        let credentials = self
            .0
            .fetch_next()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let Some(credentials) = credentials else {
            return Ok(None);
        };

        let mut result = Vec::with_capacity(credentials.len());
        for credential in credentials {
            result.push(credential.try_into()?);
        }

        Ok(Some(result))
    }
}

impl From<AskarVaultCursorParams> for askar::vault::AskarVaultCursorParams {
    fn from(value: AskarVaultCursorParams) -> Self {
        askar::vault::AskarVaultCursorParams {
            fields: value.fields,
            batch_size: value.batch_size.map(Into::into),
            limit: value.limit.map(Into::into),
            offset: value.offset.map(Into::into),
            order_by: value.order_by.map(|o| o.into()),
            sort_by_desc: value.sort_by.map(|sort_by| match sort_by {
                AskarVaultCursorSortBy::Ascending => {
                    askar::vault::AskarVaultCursorParamsSortBy::Ascending
                }
                AskarVaultCursorSortBy::Descending => {
                    askar::vault::AskarVaultCursorParamsSortBy::Descending
                }
            }),
        }
    }
}

impl From<AskarVaultCursorOrderBy> for AskarVaultCursorParamsOrderBy {
    fn from(value: AskarVaultCursorOrderBy) -> Self {
        match value {
            AskarVaultCursorOrderBy::Id => AskarVaultCursorParamsOrderBy::Id,
        }
    }
}
