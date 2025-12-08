use crate::common::Result;
pub(crate) use agent_sdk::vault::{
    CredentialEntry, Vault as ASDKVault, VaultFetchOptions as ASDKVaultFetchOptions,
};
use agent_sdk::vc;
use agent_sdk::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

use agent_sdk::vault::{DeletingSnafu, Error as ASDKError, Result as ASDKResult};
use agent_sdk::vc::oid4vp::FindVCsFailReason;

#[uniffi::remote(Record)]
pub struct CredentialEntry {
    pub credential: Credential,
    pub kid: String,
    pub id: String,
}

#[uniffi::remote(Enum)]
pub enum FindVCsFailReason {
    Paths(Vec<Vec<String>>),
    TypesNotMatched,
    CredentialsNotFound,
}

#[derive(uniffi::Enum)]
pub enum CredentialsSearchResult {
    Credentials(Vec<CredentialEntry>),
    Reason(FindVCsFailReason),
}

#[derive(uniffi::Record)]
pub struct CredentialsFindResult {
    pub(crate) data: CredentialsSearchResult,
}

#[derive(uniffi::Record)]
pub struct VaultFetchOptions {
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

impl From<VaultFetchOptions> for ASDKVaultFetchOptions {
    fn from(value: VaultFetchOptions) -> Self {
        Self {
            offset: value.offset.map(|v| v as usize),
            limit: value.limit.map(|v| v as usize),
        }
    }
}
impl From<ASDKVaultFetchOptions> for VaultFetchOptions {
    fn from(value: ASDKVaultFetchOptions) -> Self {
        Self {
            offset: value.offset.map(|v| v as u32),
            limit: value.limit.map(|v| v as u32),
        }
    }
}

#[uniffi::export(with_foreign)]
#[async_trait]
pub trait Vault: Send + Sync + Debug {
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: vc::CredentialMetadata,
    ) -> Result<String>;
    async fn delete_credential(&self, id: String) -> Result<()>;
    async fn get_credential(&self, id: String) -> Result<Option<CredentialEntry>>;
    async fn get_credentials(
        &self,
        options: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>>;
    async fn find_credentials(
        &self,
        fields: Vec<String>,
        options: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>>;
}

#[derive(Debug, Clone)]
pub struct WrappedVault(Arc<dyn Vault>);

impl WrappedVault {
    pub fn new(vault: Arc<dyn Vault>) -> Self {
        Self(vault)
    }
    pub fn inner(&self) -> Arc<dyn Vault> {
        self.0.to_owned()
    }
}

#[async_trait]
impl ASDKVault for WrappedVault {
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: &CredentialMetadata,
    ) -> ASDKResult<String> {
        self.0
            .store_credential(credential, metadata.to_owned())
            .await
            .map_err(|e| ASDKError::Storing {
                details: e.to_string(),
                location: Default::default(),
            })
    }

    async fn delete_credential(&self, id: &str) -> ASDKResult<()> {
        self.0.delete_credential(id.to_string()).await.map_err(|e| {
            DeletingSnafu {
                details: e.to_string(),
            }
            .build()
        })
    }

    async fn get_credential(&self, id: &str) -> ASDKResult<Option<CredentialEntry>> {
        self.0.get_credential(id.to_string()).await.map_err(|e| {
            DeletingSnafu {
                details: e.to_string(),
            }
            .build()
        })
    }

    async fn get_credentials(
        &self,
        options: Option<ASDKVaultFetchOptions>,
    ) -> ASDKResult<Vec<CredentialEntry>> {
        let options = options.map(Into::into);

        self.0.get_credentials(options).await.map_err(|e| {
            DeletingSnafu {
                details: e.to_string(),
            }
            .build()
        })
    }

    async fn find_credentials(
        &self,
        fields: Vec<String>,
        options: Option<ASDKVaultFetchOptions>,
    ) -> ASDKResult<Vec<CredentialEntry>> {
        let options = options.map(Into::into);

        self.0.find_credentials(fields, options).await.map_err(|e| {
            DeletingSnafu {
                details: e.to_string(),
            }
            .build()
        })
    }
}

#[uniffi::export]
fn wrap_vault_for_tests(vault: Arc<dyn Vault>) -> Arc<dyn Vault> {
    WrappedVault::new(vault).inner()
}
