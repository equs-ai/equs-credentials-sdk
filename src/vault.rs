use std::fmt::Debug;

use crate::{kms, vc};
use async_trait::async_trait;
use common_macros::DebugError;
#[cfg(test)]
use mockall::automock;
use serde::{Deserialize, Serialize};
use snafu::{Location, Snafu};

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
}

/// `Result` alias for Vault-specific [Error].
pub type Result<T> = core::result::Result<T, Error>;

/// Filter to be used in [Vault::find_credentials].
///
/// # Variants
/// - `Format(String)`: Filters credentials based on their format (e.g., "vc+sd-jwt").
/// - `Fields(Vec<String>)`: Filters credentials based on the presence of specific tag keys.
/// - `FieldValue(String, String)`: Filters credentials where a specific tag key matches a given value.
#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum CredentialFilter {
    Format(String),
    TagKeys(Vec<String>),
    Tag(String, String),
    // etc
}

/// A struct for stored `Credential` in `Vault` with some extra information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub credential: vc::Credential,
    pub kid: kms::KeyID,
    pub id: String,
}

/// An async `Vault` interface for managing Verifiable Credentials.
///
/// Should be implemented by any adapter to be used with `ASDK`.
///
/// Supports storing, retrieving and finding [vc::Credential].
#[cfg_attr(test, automock)]
#[async_trait]
pub trait Vault: Send + Sync {
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
        credential: vc::Credential,
        metadata: &vc::CredentialMetadata,
    ) -> Result<String>;

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
    /// # Returns
    ///
    /// A Vector of `CredentialEntry` on success.
    /// In case if there are no entries an empty Vector should be returned.
    ///
    /// # Errors
    ///
    /// * [Error::Resolving] - fails to revolve the values.
    async fn get_credentials(&self) -> Result<Vec<CredentialEntry>>;

    /// Find the matching `CredentialEntry`s in `Vault`
    ///
    /// # Arguments
    ///
    /// * `criterias` -  a vec of [CredentialFilter] to search for credentials.
    ///
    /// # Returns
    ///
    /// A Vector of `CredentialEntry` matched the provided `criterias` on success.
    /// In case if nothing meets the `criterias` an empty Vector should be returned.
    ///
    /// # Errors
    ///
    /// * [Error::Resolving] - fails to revolve the values.
    ///
    ///
    async fn find_credentials(
        &self,
        filters: Vec<CredentialFilter>,
    ) -> Result<Vec<CredentialEntry>>;
}

#[cfg(test)]
pub mod test_util {
    use crate::vault::{CredentialEntry, CredentialFilter, Vault};
    use crate::vc::{Credential, CredentialMetadata, VCFormat};

    pub async fn test_vault<V: Vault>(vault: V) {
        // test data
        let cred1 = "token".to_string();
        let cred1_meta = CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            kid: "1234".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            tags: vec![
                (
                    "$.vct".to_string(),
                    "https://credentials.example.com/identity_credential".to_string(),
                ),
                ("$.name".to_string(), "John".to_string()),
                ("$.email.work".to_string(), "email@email.com".to_string()),
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
            tags: vec![],
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

        let get_all_res = vault.get_credentials().await.unwrap();

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
            .find_credentials(vec![
                CredentialFilter::Format(VCFormat::SdJwtVc.to_string()),
                CredentialFilter::TagKeys(vec!["$.name".to_string()]),
                CredentialFilter::Tag("$.email.work".to_string(), "email@email.com".to_string()),
                CredentialFilter::Tag(
                    "$.vct".to_string(),
                    "https://credentials.example.com/identity_credential".to_string(),
                ),
            ])
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(find_res).unwrap(),
            serde_json::Value::Array(vec![serde_json::to_value(CredentialEntry {
                credential: Credential::SdJwt(cred1),
                kid: "1234".into(),
                id: actual_resp1.id
            })
            .unwrap()])
        );
    }
}
