use crate::vault::JsCredentialEntry;
use crate::vc::core::{JsCredential, JsCredentialMetadata};
use agent_sdk::vault::Vault;
use napi_derive::napi;
use std::sync::Arc;

/// `Native Vault`
///
/// An async `Vault` interface for managing Verifiable Credentials.
///
/// Should be implemented by any adapter to be used with `ASDK`.
///
/// Supports storing, retrieving and finding {@link Credential}
///
/// @property storeCredential - {@link NativeVault.storeCredential}
/// @property deleteCredential - {@link NativeVault.deleteCredential}
/// @property getCredential - {@link NativeVault.getCredential}
/// @property getCredentials - {@link NativeVault.getCredentials}
/// @property findCredentials - {@link NativeVault.findCredentials}
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

    /// Stores the {@link Credential} in {@link Vault}.
    ///
    /// @param {Credential} credential - the {@link Credential} to store
    /// @param {CredentialMetadata} metadata - the corresponding {@link CredentialMetadata}
    ///
    /// @returns {string} An `ID` of the stored `credential` on success
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

    /// Delete a {@link CredentialEntry} with {@link Credential} from {@link Vault}
    ///
    /// @param {string} id -  `ID` of the stored {@link CredentialEntry}
    ///
    /// @returns {void}
    #[napi]
    pub async fn delete_credential(&self, id: String) -> napi::Result<()> {
        self.0
            .delete_credential(&id)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))
    }

    /// Get a {@link CredentialEntry} with {@link Credential} from {@link Vault}
    ///
    /// @param {string} id - `ID` of the stored {@link CredentialEntry}
    ///
    /// @returns {CredentialEntry | null}
    /// * {@link CredentialEntry} on success
    /// * `null` if no {@link CredentialEntry} was found by `id`
    #[napi]
    pub async fn get_credential(&self, id: String) -> napi::Result<Option<JsCredentialEntry>> {
        let credential = self
            .0
            .get_credential(&id)
            .await
            .map_err(|err| napi::Error::from_reason(format!("{err:?}")))?;

        credential.map(|entry| entry.try_into()).transpose()
    }

    /// List all {@link CredentialEntry}s in {@link Vault}
    ///
    /// @returns {Array<CredentialEntry>}
    /// * An array of {@link CredentialEntry} on success
    /// * Empty array if there are no entries
    #[napi]
    pub async fn get_credentials(&self) -> napi::Result<Vec<JsCredentialEntry>> {
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

    /// Find the matching {@link CredentialEntry}s in {@link Vault}
    ///
    /// @param {Array<string>} fields -  an array of fields to search for credentials.
    ///
    /// @returns {Array<CredentialEntry>}
    /// * An array of {@link CredentialEntry} matched the provided `fields` on success
    /// * An empty array if nothing meets the `fields`
    #[napi]
    pub async fn find_credentials(
        &self,
        fields: Vec<String>,
    ) -> napi::Result<Vec<JsCredentialEntry>> {
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
