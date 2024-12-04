use crate::vault::{JsCredentialEntry, JsCredentialFilter};
use crate::vc::core::{JsCredential, JsCredentialMetadata};
use agent_sdk::vault;
use agent_sdk::vault::{CredentialEntry, CredentialFilter, ResolvingSnafu, StoringSnafu, Vault};
use agent_sdk::vc::{Credential, CredentialMetadata};
use async_trait::async_trait;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;

#[derive(Clone)]
#[napi(js_name = "Vault", object, object_to_js = false)]
pub struct JsVault {
    #[napi(ts_type = "(credential: Credential, metadata: CredentialMetadata) => Promise<String>")]
    pub store_credential:
        ThreadsafeFunction<(JsCredential, JsCredentialMetadata), ErrorStrategy::Fatal>,
    #[napi(ts_type = "(id: string) => Promise<CredentialEntry | null>")]
    pub get_credential: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(criteria: Array<CredentialFilter>) => Promise<Array<CredentialEntry>>")]
    pub find_credentials: ThreadsafeFunction<Vec<JsCredentialFilter>, ErrorStrategy::Fatal>,
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

    async fn find_credentials(
        &self,
        filters: Vec<CredentialFilter>,
    ) -> vault::Result<Vec<CredentialEntry>> {
        let promise: Promise<Vec<JsCredentialEntry>> = self
            .find_credentials
            .call_async(
                filters
                    .iter()
                    .map(|c| JsCredentialFilter(c.to_owned()))
                    .collect(),
            )
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
