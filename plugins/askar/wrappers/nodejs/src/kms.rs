use crate::AskarStorage;
use askar::kms::{JweDecryptBytes, Key, Kms, Signer, Verifier};
use napi::bindgen_prelude::{FromNapiValue, ToNapiValue, Uint8Array};
use napi::{sys, Error, Result, Status};
use napi_derive::napi;

/// `Askar Kms`
///
/// @method {(kt: KeyType) => Promise<string>} create - Create and store a key in {@link Kms}.
/// @method {(kid: string) => Promise<KeyHandle>} get - Returns {@link KeyHandle} for the provided `KID`
/// @method {(pk: Uint8Array) => Promise<KeyHandle>} getByPublicKey - Returns {@link KeyHandle} for the provided `Public Key`
/// @method {(jwe: string) => Promise<Buffer>} decryptToBuffer - Decrypts a compact JWE token and returns raw plaintext bytes.
///
#[napi]
pub struct AskarKms(askar::kms::AskarKms);

#[napi]
impl AskarKms {
    #[napi(constructor)]
    pub fn new(storage: &AskarStorage, profile: String) -> Self {
        let kms = askar::kms::AskarKms::new(&storage.0.clone(), profile);

        AskarKms(kms)
    }

    /// Create and store a key in `Askar Kms`.
    ///
    /// @param {KeyType} kt - a {@link KeyType} for the key.
    ///
    /// @returns {Promise<string>} - A `KeyId` for the created key on success.
    #[napi]
    pub async fn create(&self, kt: KeyType) -> Result<String> {
        self.0
            .create(kt.into(), Default::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Returns {@link KeyHandle} for the provided `KID`.
    ///
    /// @param {string} kid - a `KeyId` of the requested key.
    ///
    /// @returns {Promise<KeyHandle>} - A {@link KeyHandle} supporting basic crypto primitives on success.
    #[napi]
    pub async fn get(&self, kid: String) -> Result<AskarKeyHandle> {
        self.0
            .get(&kid)
            .await
            .map(AskarKeyHandle::new)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Returns {@link KeyHandle} for the provided public key.
    ///
    /// @param {Uint8Array} publicKey - a public key for the requested key.
    ///
    /// @returns {Promise<KeyHandle>} - A {@link KeyHandle} supporting basic crypto primitives on success.
    #[napi]
    pub async fn get_by_public_key(&self, public_key: Uint8Array) -> Result<AskarKeyHandle> {
        self.0
            .get_by_public_key(&public_key)
            .await
            .map(AskarKeyHandle::new)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Decrypts a compact JWE token using the private key stored in Askar KMS.
    ///
    /// The `kid` in the JWE protected header must match a key stored in this KMS instance.
    ///
    /// @param {string} jwe - A compact serialisation JWE token.
    ///
    /// @returns {Promise<Buffer>} - Raw plaintext bytes on success.
    #[napi]
    pub async fn decrypt_to_buffer(&self, jwe: String) -> Result<Uint8Array> {
        self.0
            .decrypt_bytes(&jwe)
            .await
            .map(|bytes| Uint8Array::from(bytes.as_slice()))
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

/// `Askar Key Handle`
///
/// @property pubKey -  {@link AskarKeyHandle.pubKey}
/// @property jwk - {@link AskarKeyHandle.jwk}
/// @property alg - {@link AskarKeyHandle.alg}
/// @method sign - {@link AskarKeyHandle.sign}
/// @method verify - {@link AskarKeyHandle.verify}
#[napi]
pub struct AskarKeyHandle {
    inner: askar::kms::AskarKeyHandle,
    /// The public key in JWK form if it's supported.
    ///
    /// * string jwk if the public key can be represented as JWK
    /// * `undefined` if the JWK-form is not supported.
    pub jwk: Option<String>,
}

#[napi]
impl AskarKeyHandle {
    pub fn new(handle: askar::kms::AskarKeyHandle) -> Self {
        let jwk = handle
            .jwk()
            .and_then(|value| serde_json::to_string(&value).ok());
        AskarKeyHandle { inner: handle, jwk }
    }

    /// Returns the public key for the corresponding handle.
    ///
    /// @returns {Array<number>} - Public key bytes.
    #[napi(getter)]
    pub fn pub_key(&self) -> Result<Vec<u8>> {
        self.inner
            .pub_key()
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Returns algorithm of the signer.
    ///
    /// @returns {Alg} - An {@link Alg} enum value.
    #[napi(getter)]
    pub fn alg(&self) -> Result<Alg> {
        self.inner.alg().try_into()
    }

    /// Sign the provided binary payload.
    ///
    /// @param {Uint8Array} payload - an array of bytes to be signed.
    ///
    /// @returns {Uint8Array} signed `payload` on success.
    #[napi]
    pub async fn sign(&self, payload: &[u8]) -> Result<Uint8Array> {
        self.inner
            .sign(payload)
            .await
            .map(Into::into)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Verifies a cryptographic signature for given binary data.
    ///
    /// @param {Uint8Array} data - the original binary data that was signed.
    /// @param {Uint8Array} signature - the corresponding signature.
    ///
    /// @returns {void}
    #[napi]
    pub async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.inner
            .verify(data, signature)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

pub enum KeyType {
    Ed25519,
    P256,
    K256,
}

impl FromNapiValue for KeyType {
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        let mut value = 0u32;
        let status = sys::napi_get_value_uint32(env, napi_val, &mut value);

        if status != sys::Status::napi_ok {
            return Err(Error::new(
                Status::from(status),
                "Failed to convert JS value to u32".to_string(),
            ));
        }

        let key_type = match value {
            0 => KeyType::Ed25519,
            1 => KeyType::P256,
            2 => KeyType::K256,
            _ => {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!("Invalid KeyType value: {}", value),
                ))
            }
        };

        Ok(key_type)
    }
}

impl From<KeyType> for askar::kms::KeyType {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Ed25519 => askar::kms::KeyType::Ed25519,
            KeyType::P256 => askar::kms::KeyType::P256,
            KeyType::K256 => askar::kms::KeyType::K256,
        }
    }
}

pub enum Alg {
    ES256,
    ES256K,
    EdDSA,
}

impl FromNapiValue for Alg {
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        let mut value = 0u32;
        let status = sys::napi_get_value_uint32(env, napi_val, &mut value);

        if status != sys::Status::napi_ok {
            return Err(Error::new(
                Status::from(status),
                "Failed to convert JS value to u32".to_string(),
            ));
        }

        let alg = match value {
            0 => Alg::ES256,
            1 => Alg::ES256K,
            2 => Alg::EdDSA,
            _ => {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!("Invalid Alg value: {}", value),
                ))
            }
        };

        Ok(alg)
    }
}

impl From<Alg> for askar::kms::Alg {
    fn from(value: Alg) -> Self {
        match value {
            Alg::ES256 => askar::kms::Alg::ES256,
            Alg::ES256K => askar::kms::Alg::ES256K,
            Alg::EdDSA => askar::kms::Alg::EdDSA,
        }
    }
}

impl TryFrom<askar::kms::Alg> for Alg {
    type Error = Error;
    fn try_from(value: askar::kms::Alg) -> Result<Self> {
        let alg = match value {
            askar::kms::Alg::ES256 => Alg::ES256,
            askar::kms::Alg::ES256K => Alg::ES256K,
            askar::kms::Alg::EdDSA => Alg::EdDSA,
            _ => {
                return Err(Error::from_reason(format!(
                    "Unsupported algorithm: {value}"
                )))
            }
        };

        Ok(alg)
    }
}

impl ToNapiValue for Alg {
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        let value = match val {
            Alg::ES256 => 0u32,
            Alg::ES256K => 1u32,
            Alg::EdDSA => 2u32,
        };

        let mut result = std::ptr::null_mut();
        let status = sys::napi_create_uint32(env, value, &mut result);

        if status != sys::Status::napi_ok {
            return Err(Error::new(
                Status::from(status),
                "Failed to convert u32 to JS value".to_string(),
            ));
        }

        Ok(result)
    }
}
