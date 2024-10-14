use agent_sdk::vault;
use agent_sdk::vault::{CredentialEntry, FindCriteria, Vault};
use agent_sdk::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use napi_derive::napi;
use std::sync::Arc;

use crate::vc::core::{JsCredential, JsCredentialMetadata};

#[derive(Clone)]
#[napi]
pub struct NativeVault(Arc<dyn Vault>);

#[napi]
impl NativeVault {
    pub fn from<V: Vault + 'static>(vault: V) -> NativeVault {
        NativeVault(Arc::new(vault))
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

#[async_trait]
impl Vault for NativeVault {
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: &CredentialMetadata,
    ) -> vault::Result<String> {
        self.0.store_credential(credential, metadata).await
    }

    async fn get_credential(&self, id: &str) -> vault::Result<Option<CredentialEntry>> {
        self.0.get_credential(id).await
    }

    async fn find_credentials(
        &self,
        criteria: FindCriteria,
    ) -> vault::Result<Vec<CredentialEntry>> {
        self.0.find_credentials(criteria).await
    }
}

#[napi(js_name = "CredentialEntry", object)]
pub struct JsCredentialEntry {
    pub credential: JsCredential,
    pub kid: String,
}

impl TryFrom<CredentialEntry> for JsCredentialEntry {
    type Error = napi::Error;

    fn try_from(value: CredentialEntry) -> napi::Result<Self> {
        Ok(JsCredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
        })
    }
}

impl TryFrom<JsCredentialEntry> for CredentialEntry {
    type Error = napi::Error;

    fn try_from(value: JsCredentialEntry) -> napi::Result<Self> {
        Ok(CredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
        })
    }
}

#[napi]
pub struct CredentialSearchCriteria(FindCriteria);

#[napi]
impl CredentialSearchCriteria {
    #[napi(factory)]
    pub fn by_type_and_format(type_: String, format: String) -> Self {
        CredentialSearchCriteria(FindCriteria::ByTypeAndFormat(type_, format))
    }
}
