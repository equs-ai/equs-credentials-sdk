use crate::vc::core::{JsAlg, JsKeyMetadata};
use async_trait::async_trait;
use equs_sdk::crypto::{Alg, JWK, Key, Signer, SigningKey, Verifier, VerifyingKey};
use equs_sdk::did::didkey::DIDKey;
use equs_sdk::did::universal::UniversalResolver;
use equs_sdk::did::{DIDBuf, DIDResolver};
use equs_sdk::jwe::{self, JweDecrypt, JweDecryptError};
use equs_sdk::kms::{
    BIP32Params, CreateOptions, ECDH1PUParams, ECDHESParams, KeyHandle, KeyID, KeyPair, KeyType,
    Kms,
};
use equs_sdk::{crypto, kms};
use napi::bindgen_prelude::{Promise, Uint8Array};
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction};
use napi::{Either, Error};
use napi_derive::napi;
use serde_json::Value;
use snafu::ResultExt;

#[napi(js_name = "KeyType")]
pub enum JsKeyType {
    Ed25519,
    P256,
    K256,
}

impl From<JsKeyType> for KeyType {
    fn from(value: JsKeyType) -> Self {
        match value {
            JsKeyType::Ed25519 => KeyType::Ed25519,
            JsKeyType::P256 => KeyType::P256,
            JsKeyType::K256 => KeyType::K256,
        }
    }
}

impl TryFrom<KeyType> for JsKeyType {
    type Error = Error;

    fn try_from(value: KeyType) -> napi::Result<Self> {
        let key_type = match value {
            KeyType::Ed25519 => JsKeyType::Ed25519,
            KeyType::P256 => JsKeyType::P256,
            KeyType::K256 => JsKeyType::K256,
            _ => return Err(Error::from_reason(format!("Unsupported key type {value}"))),
        };

        Ok(key_type)
    }
}

#[napi(object, js_name = "KeyPair")]
pub struct JsKeyPair {
    pub private_key: Option<Vec<u8>>,
    pub public_key: Vec<u8>,
}

impl From<JsKeyPair> for KeyPair {
    fn from(value: JsKeyPair) -> Self {
        KeyPair {
            private_key: value.private_key,
            public_key: value.public_key,
        }
    }
}

impl TryFrom<KeyPair> for JsKeyPair {
    type Error = napi::Error;

    fn try_from(value: KeyPair) -> Result<Self, Self::Error> {
        Ok(JsKeyPair {
            public_key: value.public_key.clone(),
            private_key: value.private_key.clone(),
        })
    }
}

#[napi(object, js_name = "ECDHESParams")]
pub struct JsECDHESParams {
    pub key_type: JsKeyType,
    pub ephem_key: JsKeyPair,
    pub recip_key: JsKeyPair,
    pub alg: Vec<u8>,
    pub apu: Vec<u8>,
    pub apv: Vec<u8>,
    pub receive: bool,
}

impl From<JsECDHESParams> for ECDHESParams {
    fn from(value: JsECDHESParams) -> Self {
        ECDHESParams {
            key_type: value.key_type.into(),
            ephem_key: value.ephem_key.into(),
            recip_key: value.recip_key.into(),
            alg: value.alg,
            apu: value.apu,
            apv: value.apv,
            receive: value.receive,
        }
    }
}

impl TryFrom<ECDHESParams> for JsECDHESParams {
    type Error = napi::Error;

    fn try_from(value: ECDHESParams) -> Result<Self, Self::Error> {
        Ok(JsECDHESParams {
            key_type: value.key_type.try_into()?,
            ephem_key: value.ephem_key.try_into()?,
            recip_key: value.recip_key.try_into()?,
            alg: value.alg,
            apu: value.apu,
            apv: value.apv,
            receive: value.receive,
        })
    }
}

#[napi(object, js_name = "ECDH1PUParams")]
pub struct JsECDH1PUParams {
    pub key_type: JsKeyType,
    pub ephem_key: JsKeyPair,
    pub send_key: JsKeyPair,
    pub recip_key: JsKeyPair,
    pub alg: Vec<u8>,
    pub apu: Vec<u8>,
    pub apv: Vec<u8>,
    pub cc_tag: Vec<u8>,
    pub receive: bool,
}

impl From<JsECDH1PUParams> for ECDH1PUParams {
    fn from(value: JsECDH1PUParams) -> Self {
        ECDH1PUParams {
            key_type: value.key_type.into(),
            ephem_key: value.ephem_key.into(),
            send_key: value.send_key.into(),
            recip_key: value.recip_key.into(),
            alg: value.alg,
            apu: value.apu,
            apv: value.apv,
            cc_tag: value.cc_tag,
            receive: value.receive,
        }
    }
}

impl TryFrom<ECDH1PUParams> for JsECDH1PUParams {
    type Error = napi::Error;

    fn try_from(value: ECDH1PUParams) -> Result<Self, Self::Error> {
        Ok(JsECDH1PUParams {
            key_type: value.key_type.try_into()?,
            ephem_key: value.ephem_key.try_into()?,
            send_key: value.send_key.try_into()?,
            recip_key: value.recip_key.try_into()?,
            alg: value.alg,
            apu: value.apu,
            apv: value.apv,
            cc_tag: value.cc_tag,
            receive: value.receive,
        })
    }
}

#[napi(object)]
pub struct MasterDeriveParams {
    pub seed: Vec<u8>,
}

#[napi(object)]
pub struct ChildDeriveParams {
    pub path: String,
    pub master_kid: String,
}

#[napi(object, js_name = "BIP32Params")]
pub struct JsBIP32Params {
    #[napi(
        ts_type = "{ type: 'MasterDerive', params: MasterDeriveParams } | { type: 'ChildDerive', params: ChildDeriveParams }"
    )]
    pub params: Either<MasterDeriveParams, ChildDeriveParams>,
}

impl TryFrom<JsBIP32Params> for BIP32Params {
    type Error = Error;

    fn try_from(value: JsBIP32Params) -> Result<Self, Self::Error> {
        match value.params {
            Either::A(master_params) => Ok(BIP32Params::MasterDerive {
                seed: master_params.seed,
            }),
            Either::B(child_params) => Ok(BIP32Params::ChildDerive {
                path: child_params.path,
                master_kid: child_params.master_kid,
            }),
        }
    }
}

impl TryFrom<BIP32Params> for JsBIP32Params {
    type Error = Error;

    fn try_from(value: BIP32Params) -> Result<Self, Self::Error> {
        match value {
            BIP32Params::MasterDerive { seed } => Ok(JsBIP32Params {
                params: Either::A(MasterDeriveParams { seed }),
            }),
            BIP32Params::ChildDerive { path, master_kid } => Ok(JsBIP32Params {
                params: Either::B(ChildDeriveParams {
                    path,
                    master_kid: master_kid.to_string(),
                }),
            }),
        }
    }
}

/// `Key Handle`
///
/// @property {Array<number>} [pubKey] - public key bytes
/// @property {string} [jwk] - jwk
/// @property {Alg} alg - Key Handle algorithm
/// @property {(payload: Uint8Array) => Promise<Uint8Array>} sign - Sign the provided binary payload.
/// @property {(data: Uint8Array, signature: Uint8Array) => Promise<void>} verify - Verifies a cryptographic signature for given binary data.
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

/// `Kms`
///
/// @property {(kt: KeyType) => Promise<string>} create - Create and store a key in {@link Kms}.
/// @property {(kid: string) => Promise<KeyHandle>} get - Returns {@link KeyHandle} for the provided `KID`
/// @property {(pk: Array<number>) => Promise<KeyHandle>} getByPublicKey - Returns {@link KeyHandle} for the provided `Public Key`
/// @property {(jwe: string) => Promise<Record<string, any>>} decrypt - Decrypts provided `JWE` token and returns a decrypted `payload`
///
#[derive(Clone)]
#[napi(js_name = "Kms", object, object_to_js = false)]
pub struct JsKms {
    #[napi(ts_type = "(kt: KeyType) => Promise<string>")]
    pub create: ThreadsafeFunction<JsKeyType, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(kid: string) => Promise<KeyHandle>")]
    pub get: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(pk: Uint8Array) => Promise<KeyHandle>")]
    pub get_by_public_key: ThreadsafeFunction<Uint8Array, ErrorStrategy::Fatal>,
    #[napi(ts_type = "(jwe: string) => Promise<Record<string, any>>")]
    pub decrypt: Option<ThreadsafeFunction<String, ErrorStrategy::Fatal>>,
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

    async fn get_by_public_key(&self, public_key: &[u8]) -> kms::Result<JsKeyHandle> {
        let promise: Promise<JsKeyHandle> = self
            .get_by_public_key
            .call_async(Uint8Array::from(public_key))
            .await
            .map_err(|err| {
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

#[async_trait]
impl JweDecrypt<JsKeyHandle> for JsKms {
    // `_kid` is unused: a callback-based KMS resolves the recipient key inside
    // its JS `decrypt` callback (from the JWE header), not by an explicit kid on
    // the Rust side. The parameter exists only to satisfy the trait.
    async fn decrypt(&self, jwe: &str, _kid: &str) -> Result<Value, JweDecryptError> {
        // A callback-based KMS holds its keys in JS and cannot derive the shared
        // secret in Rust, so decryption must be delegated to the JS `decrypt`
        // callback. Without one there is no way to decrypt.
        let Some(decrypt_js_func) = self.decrypt.as_ref() else {
            return Err(crypto::MalformedSnafu {
                details: "JsKms was constructed without a `decrypt` callback; JWE decryption is unavailable".to_string(),
            }
            .build())
            .context(kms::CryptoSnafu)
            .context(jwe::KmsSnafu);
        };

        js_decrypt_jwe(decrypt_js_func, jwe)
            .await
            .map_err(|err| {
                crypto::MalformedSnafu {
                    details: format!("Failed to decrypt JWE token. Napi status: {}", err),
                }
                .build()
            })
            .context(kms::CryptoSnafu)
            .context(jwe::KmsSnafu)
    }
}

async fn js_decrypt_jwe(
    decrypt: &ThreadsafeFunction<String, ErrorStrategy::Fatal>,
    jwe: &str,
) -> napi::Result<Value> {
    decrypt
        .call_async::<Promise<Value>>(jwe.to_string())
        .await?
        .await
}

#[napi]
pub async fn create_key_metadata(kms: JsKms) -> JsKeyMetadata {
    let (kid, kh) = kms
        .create_and_handle(kms::KeyType::P256, kms::CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(kh).unwrap();

    let vm = UniversalResolver::default()
        .resolve_into_any_verification_method(&DIDBuf::from_string(did).unwrap())
        .await
        .unwrap()
        .unwrap()
        .id
        .as_did_url()
        .to_string();

    JsKeyMetadata { did_url: vm, kid }
}

#[cfg(debug_assertions)]
pub mod test_utils {
    use super::{JsKeyHandle, JsKeyType, JsKms};
    use crate::vc::core::JsAlg;
    use equs_sdk::crypto::{Key, Signer, Verifier};
    use equs_sdk::kms::Kms;
    use napi::bindgen_prelude::Uint8Array;
    use napi_derive::napi;

    #[napi]
    pub struct KeyHandleTestHelper(JsKeyHandle);

    #[napi]
    impl KeyHandleTestHelper {
        #[napi(constructor)]
        pub fn new(key_handle: JsKeyHandle) -> Self {
            KeyHandleTestHelper(key_handle)
        }

        #[napi(getter)]
        pub fn pub_key(&self) -> Vec<u8> {
            self.0.pub_key().unwrap()
        }

        #[napi(getter)]
        pub fn jwk(&self) -> Option<String> {
            self.0.jwk().map(|jwk| jwk.to_string())
        }

        #[napi(getter)]
        pub fn alg(&self) -> JsAlg {
            self.0.alg().try_into().unwrap()
        }

        #[napi]
        pub async fn sign(&self, payload: &[u8]) -> Uint8Array {
            self.0.sign(payload).await.unwrap().into()
        }

        #[napi]
        pub async fn verify(&self, data: &[u8], signature: &[u8]) {
            self.0.verify(data, signature).await.unwrap()
        }
    }

    #[napi]
    pub struct KmsTestHelper(JsKms);

    #[napi]
    impl KmsTestHelper {
        #[napi(constructor)]
        pub fn new(kms: JsKms) -> Self {
            KmsTestHelper(kms)
        }

        #[napi]
        pub async fn create(&self, key_type: JsKeyType) -> String {
            self.0
                .create(key_type.into(), Default::default())
                .await
                .unwrap()
        }
        #[napi]
        pub async fn get(&self, id: String) -> KeyHandleTestHelper {
            self.0.get(&id).await.map(KeyHandleTestHelper).unwrap()
        }

        #[napi]
        pub async fn get_by_public_key(&self, pub_key: Uint8Array) -> KeyHandleTestHelper {
            self.0
                .get_by_public_key(&pub_key)
                .await
                .map(KeyHandleTestHelper)
                .unwrap()
        }
    }
}
