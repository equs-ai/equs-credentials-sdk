use crate::utils;
use crate::vc::{
    Credential, CredentialEntry, CredentialMetadata, JsCredential, JsCredentialEntry,
    VaultPagination,
};
use agent_sdk::vault::Vault;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct InMemVault(agent_sdk::inmem::vault::InMemVault);

#[wasm_bindgen]
impl InMemVault {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        InMemVault(agent_sdk::inmem::vault::InMemVault::new())
    }

    #[wasm_bindgen(js_name = storeCredential)]
    pub async fn store_credential(
        &self,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<String, JsError> {
        let js_credential: JsCredential = utils::convert_to_rust_object(credential)?;
        let credential = js_credential.try_into()?;
        let metadata = utils::convert_to_rust_object(metadata)?;

        self.0
            .store_credential(credential, &metadata)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }

    #[wasm_bindgen(js_name = deleteCredential)]
    pub async fn delete_credential(&self, id: String) -> Result<(), JsError> {
        self.0
            .delete_credential(&id)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))
    }

    #[wasm_bindgen(js_name = getCredential)]
    pub async fn get_credential(&self, id: &str) -> Result<Option<CredentialEntry>, JsError> {
        self.0
            .get_credential(id)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?
            .map(TryInto::try_into)
            .transpose()?
            .map(|entry: JsCredentialEntry| utils::convert_to_opaque_object_unchecked(entry))
            .transpose()
    }

    #[wasm_bindgen(js_name = getCredentials)]
    pub async fn get_credentials(
        &self,
        pagination: Option<VaultPagination>,
    ) -> Result<Vec<CredentialEntry>, JsError> {
        let pagination = if let Some(pagination) = pagination {
            let pagination: agent_sdk::vault::VaultFetchOptions =
                utils::convert_to_rust_object(pagination)?;
            Some(pagination)
        } else {
            None
        };

        let creds = self
            .0
            .get_credentials(pagination)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        let js_cred_entries: Vec<JsCredentialEntry> = creds
            .into_iter()
            .map(|cred| cred.try_into())
            .collect::<Result<_, _>>()?;

        let credential_entries = js_cred_entries
            .into_iter()
            .map(|entry| utils::convert_to_opaque_object_unchecked(entry))
            .collect::<Result<_, _>>()?;

        Ok(credential_entries)
    }

    #[wasm_bindgen(js_name = findCredentials)]
    pub async fn find_credentials(
        &self,
        fields: Vec<String>,
        pagination: Option<VaultPagination>,
    ) -> Result<Vec<CredentialEntry>, JsError> {
        let pagination = if let Some(pagination) = pagination {
            let pagination: agent_sdk::vault::VaultFetchOptions =
                utils::convert_to_rust_object(pagination)?;
            Some(pagination)
        } else {
            None
        };

        let creds = self
            .0
            .find_credentials(fields, pagination)
            .await
            .map_err(|err| JsError::new(&format!("{:?}", err)))?;

        let js_cred_entries: Vec<JsCredentialEntry> = creds
            .into_iter()
            .map(|cred| cred.try_into())
            .collect::<Result<_, _>>()?;

        let credential_entries = js_cred_entries
            .into_iter()
            .map(|entry| utils::convert_to_opaque_object_unchecked(entry))
            .collect::<Result<_, _>>()?;

        Ok(credential_entries)
    }
}

impl InMemVault {
    pub fn inner(&self) -> agent_sdk::inmem::vault::InMemVault {
        self.0.clone()
    }
}
