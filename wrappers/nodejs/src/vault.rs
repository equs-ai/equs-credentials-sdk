use crate::vc::core::{JsCredential, JsCredentialMetadata};
use agent_sdk::vault;
use agent_sdk::vault::{
    CredentialEntry, DeletingSnafu, EmptyFieldsSnafu, ResolvingSnafu, StoringSnafu, Vault,
    VaultPagination,
};
use agent_sdk::vc::oid4vp::{CredentialsFindResult, FindVCsFailReason};
use agent_sdk::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use napi::Either;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;
use serde::{Deserialize, Serialize};

/// An interface for stored {@link Credential} in {@link Vault} with some extra information.
///
/// @property {Credential} credential
/// @property {string} kid - key ID
/// @property {string} id - ID of `CredentialEntry`
#[napi(js_name = "CredentialEntry", object)]
pub struct JsCredentialEntry {
    pub credential: JsCredential,
    pub kid: String,
    pub id: String,
}

impl TryFrom<CredentialEntry> for JsCredentialEntry {
    type Error = napi::Error;

    fn try_from(value: CredentialEntry) -> napi::Result<Self> {
        Ok(JsCredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

impl TryFrom<JsCredentialEntry> for CredentialEntry {
    type Error = napi::Error;

    fn try_from(value: JsCredentialEntry) -> napi::Result<Self> {
        Ok(CredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

#[napi(string_enum, js_name = "FindVCsFailReasonType")]
#[derive(Serialize, Deserialize)]
pub enum JsFindVCsFailReasonType {
    Paths,
    TypesNotMatched,
    CredentialsNotFound,
}

/// Reasons why credentials did not pass filtering.
///
/// @property {Array<string>} paths - of field to search for
#[napi(js_name = "FindVCsFailReason", object)]
#[derive(Serialize, Deserialize)]
pub struct JsFindVCsFailReason {
    pub type_: JsFindVCsFailReasonType,
    #[napi(ts_type = "Array<Array<string>> | null")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<Vec<Vec<String>>>,
}

impl TryFrom<FindVCsFailReason> for JsFindVCsFailReason {
    type Error = napi::Error;

    fn try_from(value: FindVCsFailReason) -> napi::Result<Self> {
        let result = match value {
            FindVCsFailReason::CredentialsNotFound => JsFindVCsFailReason {
                type_: JsFindVCsFailReasonType::CredentialsNotFound,
                paths: None,
            },
            FindVCsFailReason::TypesNotMatched => JsFindVCsFailReason {
                type_: JsFindVCsFailReasonType::TypesNotMatched,
                paths: None,
            },
            FindVCsFailReason::Paths(claim_paths) => JsFindVCsFailReason {
                type_: JsFindVCsFailReasonType::Paths,
                paths: Some(claim_paths),
            },
        };
        Ok(result)
    }
}

#[napi(object, js_name = "CredentialsFindResult")]
pub struct JsCredentialsFindResult {
    pub data: Either<Vec<JsCredentialEntry>, JsFindVCsFailReason>,
}

impl TryFrom<CredentialsFindResult> for JsCredentialsFindResult {
    type Error = napi::Error;
    fn try_from(value: CredentialsFindResult) -> napi::Result<Self> {
        let data = match value {
            CredentialsFindResult::Credentials(creds) => {
                let mut result: Vec<JsCredentialEntry> = vec![];
                for cred in creds {
                    result.push(cred.try_into()?);
                }
                Either::A(result)
            }
            CredentialsFindResult::Reason(reason) => Either::B(reason.try_into()?),
        };

        Ok(Self { data })
    }
}

/// An interface for pagination in Vault. `page` * `batchSize` - number of elements to skip and then takes `batchSize` number of elements
///
/// @property {page} page - page index
/// @property {batchSize} batchSize - size of batch to get
#[napi(js_name = "VaultPagination", object)]
pub struct JsVaultPagination {
    pub page: u32,
    pub batch_size: u32,
}

impl From<JsVaultPagination> for VaultPagination {
    fn from(value: JsVaultPagination) -> Self {
        Self::new(value.page as usize, value.batch_size as usize)
    }
}
impl From<VaultPagination> for JsVaultPagination {
    fn from(value: VaultPagination) -> Self {
        Self {
            page: value.page as u32,
            batch_size: value.batch_size as u32,
        }
    }
}

/// `Vault`
///
/// An async `Vault` interface for managing Verifiable Credentials.
///
/// Should be implemented by any adapter to be used with `ASDK`.
///
/// Supports storing, retrieving and finding {@link Credential}
///
/// @property {(credential: Credential, metadata: CredentialMetadata) => Promise<string>} storeCredential - Stores the {@link Credential} in `Vault`
///
/// * `credential` - the {@link Credential} to store
///
/// * `metadata` - the corresponding {@link CredentialMetadata}
///
/// * `returns` An `ID` of the stored `credential` on success
///
/// @property {(id: string) => Promise<void>} deleteCredential - Delete a {@link CredentialEntry} with {@link Credential} from `Vault`
///
/// * `id` -  `ID` of the stored {@link CredentialEntry}
///
/// @property {(id: string) => Promise<CredentialEntry | null>} getCredential - Get a {@link CredentialEntry} with {@link Credential} from `Vault`
///
/// * `id` - `ID` of the stored {@link CredentialEntry}
///
/// * `returns` {@link CredentialEntry} on success. `null` if no {@link CredentialEntry} was found by `id`
///
/// @property {() => Promise<Array<CredentialEntry>>} getCredentials - List all {@link CredentialEntry}s in `Vault`
///
/// * `returns` an array of {@link CredentialEntry} on success. In case if there are no entries an empty array should be returned
///
/// @property {(criteria: Array<string>) => Promise<Array<CredentialEntry>>} findCredentials - Find the matching {@link CredentialEntry}s in `Vault`
///
/// * `criteria` -  an array of {@link Credential} fields to search for credentials.
///
/// * `returns` An array of {@link CredentialEntry} matched the provided `fields` on success. In case if nothing meets the `fields` an empty array should be returned
#[derive(Clone)]
#[napi(js_name = "Vault", object, object_to_js = false)]
pub struct JsVault {
    #[napi(ts_type = "(credential: Credential, metadata: CredentialMetadata) => Promise<string>")]
    pub store_credential:
        ThreadsafeFunction<(JsCredential, JsCredentialMetadata), ErrorStrategy::Fatal>,
    #[napi(ts_type = "(id: string) => Promise<void>")]
    pub delete_credential: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(id: string) => Promise<CredentialEntry | null>")]
    pub get_credential: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    #[napi(ts_type = "() => Promise<Array<CredentialEntry>>")]
    pub get_credentials: ThreadsafeFunction<Option<JsVaultPagination>, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(criteria: Array<string>) => Promise<Array<CredentialEntry>>")]
    pub find_credentials:
        ThreadsafeFunction<(Vec<String>, Option<JsVaultPagination>), ErrorStrategy::Fatal>,
}

#[async_trait]
impl Vault for JsVault {
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: &CredentialMetadata,
    ) -> vault::Result<String> {
        let credential = credential.try_into().map_err(|err: napi::Error| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })?;
        let metadata = metadata.clone().try_into().map_err(|err: napi::Error| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let promise: Promise<String> = self
            .store_credential
            .call_async((credential, metadata))
            .await
            .map_err(|err| {
                StoringSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }

    async fn delete_credential(&self, id: &str) -> vault::Result<()> {
        let promise: Promise<()> = self
            .delete_credential
            .call_async(id.to_string())
            .await
            .map_err(|err| {
                DeletingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            DeletingSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }

    async fn get_credential(&self, id: &str) -> vault::Result<Option<CredentialEntry>> {
        let promise: Promise<Option<JsCredentialEntry>> = self
            .get_credential
            .call_async(id.to_string())
            .await
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise
            .await
            .and_then(|entry| entry.map(TryInto::try_into).transpose())
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    async fn get_credentials(
        &self,
        pagination: Option<VaultPagination>,
    ) -> vault::Result<Vec<CredentialEntry>> {
        let promise: Promise<Vec<JsCredentialEntry>> = self
            .get_credentials
            .call_async(pagination.map(From::from))
            .await
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise
            .await
            .and_then(|entries| entries.into_iter().map(TryInto::try_into).collect())
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    async fn find_credentials(
        &self,
        fields: Vec<String>,
        pagination: Option<VaultPagination>,
    ) -> vault::Result<Vec<CredentialEntry>> {
        if fields.is_empty() {
            EmptyFieldsSnafu.fail()?
        };
        let promise: Promise<Vec<JsCredentialEntry>> = self
            .find_credentials
            .call_async((fields, pagination.map(From::from)))
            .await
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise
            .await
            .and_then(|entries| entries.into_iter().map(TryInto::try_into).collect())
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }
}

#[cfg(debug_assertions)]
pub mod test_utils {
    use super::{JsCredentialEntry, JsVault, JsVaultPagination};
    use crate::vc::core::{JsCredential, JsCredentialMetadata};
    use agent_sdk::vault::Vault;
    use napi_derive::napi;

    #[napi]
    pub struct VaultTestHelper(JsVault);

    #[napi]
    impl VaultTestHelper {
        #[napi(constructor)]
        pub fn new(vault: JsVault) -> Self {
            VaultTestHelper(vault)
        }

        #[napi]
        pub async fn store_credential(
            &self,
            credential: JsCredential,
            metadata: JsCredentialMetadata,
        ) -> String {
            self.0
                .store_credential(credential.try_into().unwrap(), &metadata.into())
                .await
                .unwrap()
        }

        #[napi]
        pub async fn delete_credential(&self, id: String) {
            self.0.delete_credential(&id).await.unwrap()
        }

        #[napi]
        pub async fn find_credentials(
            &self,
            fields: Vec<String>,
            pagination: Option<JsVaultPagination>,
        ) -> Vec<JsCredentialEntry> {
            self.0
                .find_credentials(fields, pagination.map(From::from))
                .await
                .unwrap()
                .iter()
                .map(|c| c.to_owned().try_into().unwrap())
                .collect()
        }

        #[napi]
        pub async fn get_credentials(
            &self,
            pagination: Option<JsVaultPagination>,
        ) -> Vec<JsCredentialEntry> {
            self.0
                .get_credentials(pagination.map(From::from))
                .await
                .unwrap()
                .iter()
                .map(|c| c.to_owned().try_into().unwrap())
                .collect()
        }

        #[napi]
        pub async fn get_credential(&self, id: String) -> Option<JsCredentialEntry> {
            self.0
                .get_credential(&id)
                .await
                .unwrap()
                .map(|c| c.to_owned().try_into().unwrap())
        }
    }
}
