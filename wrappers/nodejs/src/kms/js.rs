use agent_sdk::crypto::{Alg, Key, Signer, SigningKey, Verifier, VerifyingKey, JWK};
use agent_sdk::kms::{CreateOptions, KeyHandle, KeyID, KeyType, Kms};
use agent_sdk::{crypto, kms};
use async_trait::async_trait;
use napi::bindgen_prelude::{Promise, Uint8Array};
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi_derive::napi;

use crate::kms::JsKeyType;
use crate::vc::core::JsAlg;

#[derive(Clone)]
#[napi(js_name = "KeyHandle", object, object_to_js = false)]
pub struct JsKeyHandle {
    pub pub_key: Option<Vec<u8>>,
    pub jwk: Option<String>,
    pub alg: JsAlg,
    #[napi(ts_type = "(payload: Uint8Array) => Promise<Uint8Array>")]
    pub sign: ThreadsafeFunction<Uint8Array, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(data: Uint8Array, signature: Uint8Array) => Promise<void>")]
    pub verify: ThreadsafeFunction<(Uint8Array, Uint8Array), ErrorStrategy::Fatal>,
}

impl SigningKey for JsKeyHandle {}

impl Key for JsKeyHandle {
    fn pub_key(&self) -> crypto::Result<Vec<u8>> {
        self.pub_key
            .clone()
            .ok_or_else(|| crypto::KeyNotSupportedSnafu { type_: "public" }.build())
    }

    fn jwk(&self) -> Option<JWK> {
        self.jwk
            .as_ref()
            .and_then(|jwk| serde_json::from_str(jwk).ok())
    }
}
#[async_trait]
impl Signer for JsKeyHandle {
    fn alg(&self) -> Alg {
        self.alg.into()
    }

    async fn sign(&self, payload: &[u8]) -> crypto::Result<Vec<u8>> {
        let promise: Promise<Uint8Array> =
            self.sign.call_async(payload.into()).await.map_err(|err| {
                crypto::SigningSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map(|result| result.to_vec()).map_err(|err| {
            crypto::SigningSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

impl VerifyingKey for JsKeyHandle {}

#[async_trait]
impl Verifier for JsKeyHandle {
    async fn verify(&self, data: &[u8], signature: &[u8]) -> crypto::Result<()> {
        let promise: Promise<()> = self
            .verify
            .call_async((data.into(), signature.into()))
            .await
            .map_err(|err| {
                crypto::VerificationSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            crypto::VerificationSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}

impl KeyHandle for JsKeyHandle {}

#[derive(Clone)]
#[napi(js_name = "Kms", object, object_to_js = false)]
pub struct JsKms {
    #[napi(ts_type = "(kt: KeyType) => Promise<string>")]
    pub create: ThreadsafeFunction<JsKeyType, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(kid: string) => Promise<KeyHandle>")]
    pub get: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
}

#[async_trait]
impl Kms<JsKeyHandle> for JsKms {
    async fn create(&self, kt: KeyType, _: CreateOptions) -> kms::Result<KeyID> {
        let kt = kt.try_into().map_err(|err: napi::Error| {
            kms::CreationSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        let promise: Promise<String> = self.create.call_async(kt).await.map_err(|err| {
            kms::CreationSnafu {
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
                kms::ResolvingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        promise.await.map_err(|err| {
            kms::ResolvingSnafu {
                details: err.to_string(),
            }
            .build()
        })
    }
}
