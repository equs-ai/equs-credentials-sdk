use crate::vault::JsCredentialEntry;
use crate::vc::core::{JsCredential, JsCredentialMetadata};
use agent_sdk::vault;
use agent_sdk::vault::{
    CredentialEntry, DeletingSnafu, EmptyFieldsSnafu, ResolvingSnafu, StoringSnafu, Vault,
};
use agent_sdk::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;

/// `Vault`
///
/// An async `Vault` interface for managing Verifiable Credentials.
///
/// Should be implemented by any adapter to be used with `ASDK`.
///
/// Supports storing, retrieving and finding {@link Credential}
///
/// @property {(credential: Credential, metadata: CredentialMetadata) => Promise<string>} storeCredential - Stores the {@link Credential} in `Vault`
///
/// * `credential` - the {@link Credential} to store
///
/// * `metadata` - the corresponding {@link CredentialMetadata}
///
/// * `returns` An `ID` of the stored `credential` on success
///
/// @property {(id: string) => Promise<void>} deleteCredential - Delete a {@link CredentialEntry} with {@link Credential} from `Vault`
///
/// * `id` -  `ID` of the stored {@link CredentialEntry}
///
/// @property {(id: string) => Promise<CredentialEntry | null>} getCredential - Get a {@link CredentialEntry} with {@link Credential} from `Vault`
///
/// * `id` - `ID` of the stored {@link CredentialEntry}
///
/// * `returns` {@link CredentialEntry} on success. `null` if no {@link CredentialEntry} was found by `id`
///
/// @property {() => Promise<Array<CredentialEntry>>} getCredentials - List all {@link CredentialEntry}s in `Vault`
///
/// * `returns` an array of {@link CredentialEntry} on success. In case if there are no entries an empty array should be returned
///
/// @property {(criteria: Array<string>) => Promise<Array<CredentialEntry>>} findCredentials - Find the matching {@link CredentialEntry}s in `Vault`
///
/// * `criteria` -  an array of {@link Credential} fields to search for credentials.
///
/// * `returns` An array of {@link CredentialEntry} matched the provided `fields` on success. In case if nothing meets the `fields` an empty array should be returned
#[derive(Clone)]
#[napi(js_name = "Vault", object, object_to_js = false)]
pub struct JsVault {
    #[napi(ts_type = "(credential: Credential, metadata: CredentialMetadata) => Promise<string>")]
    pub store_credential:
        ThreadsafeFunction<(JsCredential, JsCredentialMetadata), ErrorStrategy::Fatal>,
    #[napi(ts_type = "(id: string) => Promise<void>")]
    pub delete_credential: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(id: string) => Promise<CredentialEntry | null>")]
    pub get_credential: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    #[napi(ts_type = "() => Promise<Array<CredentialEntry>>")]
    pub get_credentials: ThreadsafeFunction<(), ErrorStrategy::Fatal>,
    #[napi(ts_type = "(criteria: Array<string>) => Promise<Array<CredentialEntry>>")]
    pub find_credentials: ThreadsafeFunction<Vec<String>, ErrorStrategy::Fatal>,
}

#[async_trait]
impl Vault for JsVault {
    async fn store_credential(
        &self,
        credential: Credential,
        metadata: &CredentialMetadata,
    ) -> vault::Result<String> {
        let credential = credential.try_into().map_err(|err: napi::Error| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })?;
        let metadata = metadata.clone().try_into().map_err(|err: napi::Error| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let promise: Promise<String> = self
            .store_credential
            .call_async((credential, metadata))
            .await
            .map_err(|err| {
                StoringSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            StoringSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }

    async fn delete_credential(&self, id: &str) -> vault::Result<()> {
        let promise: Promise<()> = self
            .delete_credential
            .call_async(id.to_string())
            .await
            .map_err(|err| {
                DeletingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            DeletingSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }

    async fn get_credential(&self, id: &str) -> vault::Result<Option<CredentialEntry>> {
        let promise: Promise<Option<JsCredentialEntry>> = self
            .get_credential
            .call_async(id.to_string())
            .await
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise
            .await
            .and_then(|entry| entry.map(TryInto::try_into).transpose())
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    async fn get_credentials(&self) -> vault::Result<Vec<CredentialEntry>> {
        let promise: Promise<Vec<JsCredentialEntry>> =
            self.get_credentials.call_async(()).await.map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise
            .await
            .and_then(|entries| entries.into_iter().map(TryInto::try_into).collect())
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    async fn find_credentials(&self, fields: Vec<String>) -> vault::Result<Vec<CredentialEntry>> {
        if fields.is_empty() {
            EmptyFieldsSnafu.fail()?
        };
        let promise: Promise<Vec<JsCredentialEntry>> = self
            .find_credentials
            .call_async(fields)
            .await
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise
            .await
            .and_then(|entries| entries.into_iter().map(TryInto::try_into).collect())
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }
}
