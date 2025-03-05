use crate::AskarStorage;
use askar::kms::{Key, Kms, Signer, Verifier};
use napi::bindgen_prelude::{FromNapiValue, ToNapiValue, Uint8Array};
use napi::{sys, Error, Result, Status};
use napi_derive::napi;

#[napi]
pub struct AskarKms(askar::kms::AskarKms);

#[napi]
impl AskarKms {
    #[napi(constructor)]
    pub fn new(storage: &AskarStorage) -> Self {
        let storage = storage.clone();
        let kms = askar::kms::AskarKms::new(storage.0.clone());

        AskarKms(kms)
    }

    #[napi]
    pub async fn create(&self, kt: KeyType) -> Result<String> {
        self.0
            .create(kt.into(), Default::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn get(&self, kid: String) -> Result<AskarKeyHandle> {
        self.0
            .get(&kid)
            .await
            .map(AskarKeyHandle::new)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn get_by_public_key(&self, public_key: Vec<u8>) -> Result<AskarKeyHandle> {
        self.0
            .get_by_public_key(public_key.as_slice())
            .await
            .map(AskarKeyHandle::new)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[allow(clippy::missing_safety_doc)]
    #[napi]
    pub async unsafe fn close_kms(&mut self) -> Result<()> {
        self.0
            .to_owned()
            .close_kms()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(())
    }
}

#[napi]
pub struct AskarKeyHandle {
    inner: askar::kms::AskarKeyHandle,
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
    #[napi(getter)]
    pub fn pub_key(&self) -> Result<Vec<u8>> {
        self.inner
            .pub_key()
            .map(Into::into)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi(getter)]
    pub fn alg(&self) -> Result<Alg> {
        self.inner.alg().try_into()
    }

    #[napi]
    pub async fn sign(&self, payload: &[u8]) -> Result<Uint8Array> {
        self.inner
            .sign(payload)
            .await
            .map(Into::into)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

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
