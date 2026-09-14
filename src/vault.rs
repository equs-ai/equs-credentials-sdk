//! APIs for implementing Verifiable Credentials Vault

use crate::utils::wasm::{WasmNotSend, WasmNotSync};
use crate::vc::Credential;
use crate::{kms, vc};
use async_trait::async_trait;
use common_macros::DebugError;
use jsonpath_rust::JsonPathParserError;
#[cfg(test)]
use mockall::automock;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};
use std::fmt::Debug;

/// `Vault` Error.
///
/// All implementations of [Vault] should leverage this enum for error handling.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Unsupported credential format: {format}"))]
    FormatNotSupported { format: String },
    #[snafu(display("Credential storing error: {details}"))]
    Storing {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Credential fetching error: {details}"))]
    Fetching {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Credential deleting error: {details}"))]
    Deleting {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Credential resolving error: {details}"))]
    Resolving {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("VC error: {details}"))]
    VC {
        details: String,
        #[snafu(implicit)]
        location: Location,
    },

    #[snafu(display("Claims parsing error"))]
    ClaimsParsing { source: vc::formats::Error },

    #[snafu(display("Cannot create JSONPath"))]
    CannotCreateJSONPath { source: JsonPathParserError },

    #[snafu(display("Unsupported credential format: {format}"))]
    UnsupportedCredentialFormat { format: String },

    #[snafu(display("Empty fields provided"))]
    EmptyFields,

    #[snafu(display("Pagination parsing"))]
    PaginationParsing { details: String },

    #[snafu(display("Error during claims validation: {details}"))]
    ClaimsValidation { details: String },

    #[snafu(display("Error during getting session: {details}"))]
    Session { details: String },

    #[snafu(display("Error during conversion to credential entry: {details}"))]
    ConversionToEntry { details: String },
}

/// `Result` alias for Vault-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// A struct for stored `Credential` in `Vault` with some extra information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub credential: Credential,
    pub kid: kms::KeyID,
    pub id: String,
}

/// A struct for pagination in Vault
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFetchOptions {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// An async `Vault` interface for managing Verifiable Credentials.
///
/// Should be implemented by any adapter.
///
/// Supports storing, retrieving and finding [vc::Credential].
#[cfg_attr(test, automock)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Vault: WasmNotSend + WasmNotSync {
    /// Stores the `Credential` in `Vault`.
    ///
    /// # Arguments
    ///
    /// * `credential` - the `Credential` to store.
    /// * `metadata` - the corresponding `CredentialMetadata`.
    ///
    /// # Returns
    ///
    /// An `ID` of the stored `credential` on success.
    ///
    /// # Errors
    ///
    /// * [Error::FormatNotSupported] - format is not supported by the `Vault`.
    /// * [Error::VC] - issues with `Credential` processing.
    /// * [Error::Storing] - fails to store the values.
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: &vc::CredentialMetadata,
    ) -> Result<String>;

    /// Delete a `CredentialEntry` with `Credential` from `Vault`
    ///
    /// # Arguments
    ///
    /// * `id` -  `ID` of the stored [CredentialEntry].
    ///
    /// # Returns
    ///
    /// `()` on success.
    ///
    /// # Errors
    ///
    /// * [Error::Deleting] - fails to delete the `Credential`.
    async fn delete_credential(&self, id: &str) -> Result<()>;

    /// Get a `CredentialEntry` with `Credential` from `Vault`
    ///
    /// # Arguments
    ///
    /// * `id` -  `ID` of the stored [CredentialEntry].
    ///
    /// # Returns
    ///
    /// `Some(CredentialEntry)` on success.
    /// `None` if no `CredentialEntry` was found by `id`.
    ///
    /// # Errors
    ///
    /// * [Error::Resolving] - fails to access the storage.
    async fn get_credential(&self, id: &str) -> Result<Option<CredentialEntry>>;

    /// List all `CredentialEntry`s in `Vault`
    ///
    /// # Arguments
    ///
    /// * `pagination` -  an optional [VaultFetchOptions] field for results' pagination.
    ///
    /// # Returns
    ///
    /// A Vector of `CredentialEntry` on success.
    /// In case if there are no entries an empty Vector should be returned.
    ///
    /// # Errors
    ///
    /// * [Error::Resolving] - fails to resolve the values.
    async fn get_credentials(
        &self,
        pagination: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>>;

    /// Find the matching `CredentialEntry`s in `Vault`
    ///
    /// # Arguments
    ///
    /// * `fields` -  a vec of fields to search for credentials.
    /// * `pagination` -  an optional [VaultFetchOptions] field for results' pagination.
    ///
    /// # Returns
    ///
    /// A Vector of `CredentialEntry` matched the provided `fields` on success.
    /// In case if nothing meets the `fields` an empty Vector should be returned.
    ///
    /// # Errors
    ///
    /// * [Error::Resolving] - fails to resolve the values.
    ///
    ///
    async fn find_credentials(
        &self,
        fields: Vec<String>,
        pagination: Option<VaultFetchOptions>,
    ) -> Result<Vec<CredentialEntry>>;
}

#[cfg(test)]
pub mod test_util {
    use crate::vault::{CredentialEntry, Vault};
    use crate::vc::{Credential, CredentialMetadata, VCFormat};

    pub async fn test_vault<V: Vault>(vault: V) {
        // test data
        let cred1 = "token".to_string();
        let cred1_meta = CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid: "1234".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            fields: vec![
                "$.vct".to_string(),
                "$.name".to_string(),
                "$.email.work".to_string(),
            ],
        };
        let cred2str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let cred2: crate::vc::formats::json_ld_vc::VC = serde_json::from_str(cred2str).unwrap();
        let cred2_meta = CredentialMetadata {
            type_: "VerifiableCredential".into(),
            kid: "1234".into(),
            format: VCFormat::LdpVc,
            alg: None,
            fields: vec![],
        };

        let cred1_id = vault
            .store_credential(Credential::SdJwt(cred1.clone()), &cred1_meta)
            .await
            .unwrap();
        let cred2_id = vault
            .store_credential(Credential::LdpVc(cred2.clone()), &cred2_meta)
            .await
            .unwrap();

        let get1_res = vault.get_credential(&cred1_id).await.unwrap();
        let get2_res = vault.get_credential(&cred2_id).await.unwrap();

        let actual_resp1 = get1_res.unwrap();
        assert_eq!(
            serde_json::to_value(&actual_resp1).unwrap(),
            serde_json::to_value(CredentialEntry {
                credential: Credential::SdJwt(cred1.clone()),
                kid: "1234".into(),
                id: actual_resp1.clone().id
            })
            .unwrap(),
        );

        let actual_resp2 = get2_res.unwrap();
        assert_eq!(
            serde_json::to_value(&actual_resp2).unwrap(),
            serde_json::to_value(CredentialEntry {
                credential: Credential::LdpVc(cred2.clone()),
                kid: "1234".into(),
                id: actual_resp2.clone().id
            })
            .unwrap(),
        );

        let get_all_res = vault.get_credentials(None).await.unwrap();

        let serde_json::Value::Array(get_all_values) = serde_json::to_value(&get_all_res).unwrap()
        else {
            panic!("failed to serialize credentials as json array");
        };

        let expected_entry_sd_jwt = CredentialEntry {
            credential: Credential::SdJwt(cred1.clone()),
            kid: "1234".into(),
            id: actual_resp1.clone().id,
        };

        let expected_entry_ldp_vc = CredentialEntry {
            credential: Credential::LdpVc(cred2),
            kid: "1234".into(),
            id: actual_resp2.id,
        };

        assert!(get_all_values.contains(&serde_json::to_value(expected_entry_sd_jwt).unwrap()));
        assert!(get_all_values.contains(&serde_json::to_value(expected_entry_ldp_vc).unwrap()));

        let find_res = vault
            .find_credentials(
                vec![
                    "format".to_string(),
                    "$.name".to_string(),
                    "$.email.work".to_string(),
                    "$.vct".to_string(),
                ],
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(find_res).unwrap(),
            serde_json::Value::Array(vec![
                serde_json::to_value(CredentialEntry {
                    credential: Credential::SdJwt(cred1),
                    kid: "1234".into(),
                    id: actual_resp1.id
                })
                .unwrap()
            ])
        );

        vault.delete_credential(&cred1_id).await.unwrap();
        let get1_res = vault.get_credential(&cred1_id).await.unwrap();
        assert!(get1_res.is_none());
    }
}
