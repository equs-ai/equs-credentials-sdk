use crate::vault::{CredentialSearchCriteria, JsCredentialEntry};
use crate::vc::core::{JsCredential, JsCredentialMetadata};
use agent_sdk::vault::Vault;
use napi_derive::napi;
use std::sync::Arc;

#[derive(Clone)]
#[napi]
pub struct NativeVault(Arc<dyn Vault>);

#[napi]
impl NativeVault {
    pub fn from<V: Vault + 'static>(vault: V) -> NativeVault {
        NativeVault(Arc::new(vault))
    }

    pub fn inner(&self) -> &dyn Vault {
        self.0.as_ref()
    }

    #[napi]
    pub async fn store_credential(
        &self,
        credential: JsCredential,
        metadata: JsCredentialMetadata,
    ) -> napi::Result<String> {
        self.0
            .store_credential(credential.try_into()?, &metadata.into())
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn get_credential(&self, id: String) -> napi::Result<Option<JsCredentialEntry>> {
        let credential = self
            .0
            .get_credential(&id)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))?;

        credential.map(|entry| entry.try_into()).transpose()
    }

    #[napi]
    pub async fn find_credentials(
        &self,
        criteria: &CredentialSearchCriteria,
    ) -> napi::Result<Vec<JsCredentialEntry>> {
        let credentials = self
            .0
            .find_credentials(criteria.0.clone())
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))?;

        credentials
            .into_iter()
            .map(|entry| entry.try_into())
            .collect()
    }
}
