use crate::utils;
use crate::vc::{Credential, CredentialMetadata, JsCredential, JsCredentialEntry, VaultPagination};
use agent_sdk::vault::{DeletingSnafu, PaginationParsingSnafu, ResolvingSnafu, StoringSnafu};
use async_trait::async_trait;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Vault")]
    pub type Vault;

    #[wasm_bindgen(structural, method, catch,  js_name = storeCredential)]
    pub async fn store_credential(
        this: &Vault,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<js_sys::JsString, JsValue>;

    #[wasm_bindgen(structural, method, catch, js_name = deleteCredential)]
    pub async fn delete_credential(this: &Vault, id: &str) -> Result<(), JsValue>;

    #[wasm_bindgen(structural, method, catch, js_name = getCredential)]
    pub async fn get_credential(this: &Vault, id: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(structural, method, catch, js_name = getCredentials)]
    pub async fn get_credentials(
        this: &Vault,
        pagination: Option<VaultPagination>,
    ) -> Result<js_sys::Array, JsValue>;

    #[wasm_bindgen(structural, method, catch, js_name = findCredentials)]
    pub async fn find_credentials(
        this: &Vault,
        fields: Vec<String>,
        pagination: Option<VaultPagination>,
    ) -> Result<js_sys::Array, JsValue>;
}

pub(crate) struct JsVault(Vault);

impl JsVault {
    pub fn new(vault: Vault) -> Self {
        Self(vault)
    }

    fn convert_from_js_credential_entry(
        credential_entry: JsValue,
    ) -> agent_sdk::vault::Result<agent_sdk::vault::CredentialEntry> {
        let js_credential_entry: JsCredentialEntry =
            serde_wasm_bindgen::from_value(credential_entry).map_err(|e| {
                ResolvingSnafu {
                    details: format!("Credential Entry conversion failed {:?}", e),
                }
                .build()
            })?;

        js_credential_entry.try_into().map_err(|e| {
            ResolvingSnafu {
                details: format!("Credential Entry conversion failed {:?}", e),
            }
            .build()
        })
    }
}

#[async_trait(?Send)]
impl agent_sdk::vault::Vault for JsVault {
    async fn store_credential(
        &self,
        credential: agent_sdk::vc::Credential,
        metadata: &agent_sdk::vc::CredentialMetadata,
    ) -> agent_sdk::vault::Result<String> {
        let credential = credential
            .try_into()
            .and_then(|credential: JsCredential| {
                utils::convert_to_opaque_object_unchecked(credential)
            })
            .map_err(|e| {
                StoringSnafu {
                    details: format!("Credential conversion failed: {:?}", e),
                }
                .build()
            })?;

        let metadata = utils::convert_to_opaque_object_unchecked(metadata).map_err(|e| {
            StoringSnafu {
                details: format!("Credential Metadata conversion failed: {:?}", e),
            }
            .build()
        })?;

        let credential_id = self
            .0
            .store_credential(credential, metadata)
            .await
            .map_err(|e| {
                StoringSnafu {
                    details: utils::js_value_to_string(e),
                }
                .build()
            })?;

        credential_id.as_string().ok_or_else(|| {
            StoringSnafu {
                details: format!("Credential ID conversion failed: {credential_id}"),
            }
            .build()
        })
    }

    async fn delete_credential(&self, id: &str) -> agent_sdk::vault::Result<()> {
        self.0.delete_credential(id).await.map_err(|e| {
            DeletingSnafu {
                details: utils::js_value_to_string(e),
            }
            .build()
        })
    }

    async fn get_credential(
        &self,
        id: &str,
    ) -> agent_sdk::vault::Result<Option<agent_sdk::vault::CredentialEntry>> {
        let credential_entry = self.0.get_credential(id).await.map_err(|e| {
            ResolvingSnafu {
                details: utils::js_value_to_string(e),
            }
            .build()
        })?;

        if credential_entry.is_undefined() || credential_entry.is_null() {
            Ok(None)
        } else {
            Self::convert_from_js_credential_entry(credential_entry).map(Some)
        }
    }

    async fn get_credentials(
        &self,
        pagination: Option<agent_sdk::vault::VaultFetchOptions>,
    ) -> agent_sdk::vault::Result<Vec<agent_sdk::vault::CredentialEntry>> {
        let pagination = if let Some(pagination) = pagination {
            let pagination: VaultPagination =
                utils::convert_to_opaque_object(pagination).map_err(|_| {
                    PaginationParsingSnafu {
                        details: "Could not convert pagination to an opaque object".to_string(),
                    }
                    .build()
                })?;
            Some(pagination)
        } else {
            None
        };

        let credential_entries = self.0.get_credentials(pagination).await.map_err(|e| {
            ResolvingSnafu {
                details: utils::js_value_to_string(e),
            }
            .build()
        })?;

        credential_entries
            .into_iter()
            .map(Self::convert_from_js_credential_entry)
            .collect()
    }

    async fn find_credentials(
        &self,
        fields: Vec<String>,
        pagination: Option<agent_sdk::vault::VaultFetchOptions>,
    ) -> agent_sdk::vault::Result<Vec<agent_sdk::vault::CredentialEntry>> {
        let pagination = if let Some(pagination) = pagination {
            let pagination: VaultPagination =
                utils::convert_to_opaque_object(pagination).map_err(|_| {
                    PaginationParsingSnafu {
                        details: "Could not convert pagination to an opaque object".to_string(),
                    }
                    .build()
                })?;
            Some(pagination)
        } else {
            None
        };

        let credential_entries =
            self.0
                .find_credentials(fields, pagination)
                .await
                .map_err(|e| {
                    ResolvingSnafu {
                        details: utils::js_value_to_string(e),
                    }
                    .build()
                })?;

        credential_entries
            .into_iter()
            .map(Self::convert_from_js_credential_entry)
            .collect()
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use crate::utils;
    use crate::vault::JsVault;
    use crate::vc::{
        Credential, CredentialEntry, CredentialMetadata, JsCredential, JsCredentialEntry,
        VaultPagination,
    };
    use agent_sdk::vault::{PaginationParsingSnafu, Vault};
    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen]
    struct VaultTestHelper(JsVault);

    #[wasm_bindgen]
    impl VaultTestHelper {
        #[wasm_bindgen(constructor)]
        pub fn new(vault: crate::vault::Vault) -> Self {
            utils::set_panic_hook();
            VaultTestHelper(JsVault(vault))
        }

        #[wasm_bindgen(js_name = storeCredential)]
        pub async fn store_credential(
            &self,
            credential: Credential,
            metadata: CredentialMetadata,
        ) -> String {
            let js_credential: JsCredential = utils::convert_to_rust_object(credential).unwrap();
            let credential = js_credential.try_into().unwrap();
            let metadata = utils::convert_to_rust_object(metadata).unwrap();

            self.0
                .store_credential(credential, &metadata)
                .await
                .unwrap()
        }

        #[wasm_bindgen(js_name = deleteCredential)]
        pub async fn delete_credential(&self, id: &str) {
            self.0.delete_credential(id).await.unwrap()
        }

        #[wasm_bindgen(js_name = getCredential)]
        pub async fn get_credential(&self, id: &str) -> Option<CredentialEntry> {
            self.0
                .get_credential(id)
                .await
                .unwrap()
                .map(TryInto::try_into)
                .transpose()
                .unwrap()
                .map(|entry: JsCredentialEntry| utils::convert_to_opaque_object_unchecked(entry))
                .transpose()
                .unwrap()
        }

        #[wasm_bindgen(js_name = getCredentials)]
        pub async fn get_credentials(
            &self,
            pagination: Option<VaultPagination>,
        ) -> Vec<CredentialEntry> {
            let pagination = if let Some(pagination) = pagination {
                let pagination: agent_sdk::vault::VaultFetchOptions =
                    utils::convert_to_rust_object(pagination)
                        .map_err(|_| {
                            PaginationParsingSnafu {
                                details: "Could not convert pagination to a rust object"
                                    .to_string(),
                            }
                            .build()
                        })
                        .unwrap();
                Some(pagination)
            } else {
                None
            };
            let creds = self.0.get_credentials(pagination).await.unwrap();

            let js_cred_entries: Vec<JsCredentialEntry> = creds
                .into_iter()
                .map(|cred| cred.try_into())
                .collect::<Result<_, _>>()
                .unwrap();

            js_cred_entries
                .into_iter()
                .map(|entry| utils::convert_to_opaque_object_unchecked(entry))
                .collect::<Result<_, _>>()
                .unwrap()
        }

        #[wasm_bindgen(js_name = findCredentials)]
        pub async fn find_credentials(
            &self,
            fields: Vec<String>,
            pagination: Option<VaultPagination>,
        ) -> Vec<CredentialEntry> {
            let pagination = if let Some(pagination) = pagination {
                let pagination: agent_sdk::vault::VaultFetchOptions =
                    utils::convert_to_rust_object(pagination)
                        .map_err(|_| {
                            PaginationParsingSnafu {
                                details: "Could not convert pagination to a rust object"
                                    .to_string(),
                            }
                            .build()
                        })
                        .unwrap();
                Some(pagination)
            } else {
                None
            };

            let creds = self.0.find_credentials(fields, pagination).await.unwrap();

            let js_cred_entries: Vec<JsCredentialEntry> = creds
                .into_iter()
                .map(|cred| cred.try_into())
                .collect::<Result<_, _>>()
                .unwrap();

            js_cred_entries
                .into_iter()
                .map(|entry| utils::convert_to_opaque_object_unchecked(entry))
                .collect::<Result<_, _>>()
                .unwrap()
        }
    }
}
