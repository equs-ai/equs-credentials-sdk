use crate::kms::JsKeyHandle;
use crate::kms::{JsECDH1PUParams, JsECDHESParams, JsKeyType};
use agent_sdk::kms;
use agent_sdk::kms::{
    CreateOptions, CreationSnafu, DerivationSnafu, DerivativeKms, ECDH1PUParams, ECDHESParams,
    KeyID, KeyType, Kms, ResolvingSnafu,
};
use async_trait::async_trait;
use napi::bindgen_prelude::{Promise, Uint8Array};
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;

#[derive(Clone)]
#[napi(js_name = "DIDCommKms", object, object_to_js = false)]
pub struct DIDCommKms {
    #[napi(ts_type = "(kt: KeyType) => Promise<string>")]
    pub create: ThreadsafeFunction<JsKeyType, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(kid: string) => Promise<KeyHandle>")]
    pub get: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(pk: Uint8Array) => Promise<KeyHandle>")]
    pub get_by_public_key: ThreadsafeFunction<Uint8Array, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(params: ECDH1PUParams) => Promise<Array<number>>")]
    pub derive_ecdh1pu: ThreadsafeFunction<JsECDH1PUParams, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(params: ECDHESParams) => Promise<Array<number>>")]
    pub derive_ecdhes: ThreadsafeFunction<JsECDHESParams, ErrorStrategy::Fatal>,
}

#[async_trait]
impl Kms<JsKeyHandle> for DIDCommKms {
    async fn create(&self, kt: KeyType, _: CreateOptions) -> kms::Result<KeyID> {
        let kt = kt.try_into().map_err(|err: napi::Error| {
            CreationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let promise: Promise<String> = self.create.call_async(kt).await.map_err(|err| {
            CreationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        promise.await.map_err(|err| {
            kms::CreationSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }

    async fn get(&self, kid: &KeyID) -> kms::Result<JsKeyHandle> {
        let promise: Promise<JsKeyHandle> =
            self.get.call_async(kid.to_string()).await.map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            ResolvingSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }

    async fn get_by_public_key(&self, public_key: &[u8]) -> kms::Result<JsKeyHandle> {
        let promise: Promise<JsKeyHandle> = self
            .get_by_public_key
            .call_async(Uint8Array::from(public_key))
            .await
            .map_err(|err| {
                ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            ResolvingSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

#[async_trait]
impl DerivativeKms<ECDH1PUParams> for DIDCommKms {
    type Output = Vec<u8>;

    async fn derive(&self, params: ECDH1PUParams) -> kms::Result<Self::Output> {
        let params = params.try_into().map_err(|err: napi::Error| {
            DerivationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;
        let promise: Promise<Vec<u8>> =
            self.derive_ecdh1pu
                .call_async(params)
                .await
                .map_err(|err| {
                    DerivationSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;

        promise.await.map_err(|err| {
            DerivationSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

#[async_trait]
impl DerivativeKms<ECDHESParams> for DIDCommKms {
    type Output = Vec<u8>;

    async fn derive(&self, params: ECDHESParams) -> kms::Result<Self::Output> {
        let params = params.try_into().map_err(|err: napi::Error| {
            DerivationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;
        let promise: Promise<Vec<u8>> =
            self.derive_ecdhes.call_async(params).await.map_err(|err| {
                DerivationSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            DerivationSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}
