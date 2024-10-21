use agent_sdk::vault::{CredentialEntry, FindCriteria, Vault};
use agent_sdk::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use napi::Either;

use crate::vault::JsVault;
use crate::vault::NativeVault;

#[derive(Clone)]
pub enum UnifiedVault {
    Js(JsVault),
    Native(NativeVault),
}

#[async_trait]
impl Vault for UnifiedVault {
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: &CredentialMetadata,
    ) -> agent_sdk::vault::Result<String> {
        match self {
            UnifiedVault::Js(js) => js.store_credential(credential, metadata).await,
            UnifiedVault::Native(native) => {
                native.inner().store_credential(credential, metadata).await
            }
        }
    }

    async fn get_credential(&self, id: &str) -> agent_sdk::vault::Result<Option<CredentialEntry>> {
        match self {
            UnifiedVault::Js(js) => js.get_credential(id).await,
            UnifiedVault::Native(native) => native.inner().get_credential(id).await,
        }
    }

    async fn find_credentials(
        &self,
        criteria: FindCriteria,
    ) -> agent_sdk::vault::Result<Vec<CredentialEntry>> {
        match self {
            UnifiedVault::Js(js) => js.find_credentials(criteria).await,
            UnifiedVault::Native(native) => native.inner().find_credentials(criteria).await,
        }
    }
}

impl From<Either<&NativeVault, JsVault>> for UnifiedVault {
    fn from(value: Either<&NativeVault, JsVault>) -> Self {
        match value {
            Either::A(native) => UnifiedVault::Native(native.clone()),
            Either::B(js) => UnifiedVault::Js(js),
        }
    }
}
