use crate::vault::JsCredentialEntry;
use crate::vc::core::{JsCredential, JsCredentialMetadata};
use agent_sdk::vault::Vault;
use napi::Result;
use napi_derive::napi;

#[derive(Clone)]
#[napi]
pub struct InMemVault(agent_sdk::inmem::vault::InMemVault);

#[napi]
impl InMemVault {
    #[napi(constructor)]
    pub fn new() -> Self {
        let vault = agent_sdk::inmem::vault::InMemVault::new();
        InMemVault(vault)
    }

    #[napi]
    pub async fn store_credential(
        &self,
        credential: JsCredential,
        metadata: JsCredentialMetadata,
    ) -> Result<String> {
        self.0
            .store_credential(credential.try_into()?, &metadata.into())
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    #[napi]
    pub async fn delete_credential(&self, id: String) -> Result<()> {
        self.0
            .delete_credential(&id)
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
    pub async fn get_credentials(&self) -> Result<Vec<JsCredentialEntry>> {
        let credentials = self
            .0
            .get_credentials()
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))?;

        credentials
            .into_iter()
            .map(|entry| entry.try_into())
            .collect()
    }

    #[napi]
    pub async fn find_credentials(&self, fields: Vec<String>) -> Result<Vec<JsCredentialEntry>> {
        let credentials = self
            .0
            .find_credentials(fields)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))?;

        credentials
            .into_iter()
            .map(|entry| entry.try_into())
            .collect()
    }
}

impl Default for InMemVault {
    fn default() -> Self {
        let vault = agent_sdk::inmem::vault::InMemVault::new();
        InMemVault(vault)
    }
}
