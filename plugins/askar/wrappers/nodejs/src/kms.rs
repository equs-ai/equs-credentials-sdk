use crate::AskarStorage;
use askar::kms::{Key, Kms, Signer, Verifier};
use napi::bindgen_prelude::Uint8Array;
use napi::{Error, Result};
use napi_derive::napi;

#[napi]
pub struct InternalAskarKms(askar::kms::AskarKms);

#[napi]
impl InternalAskarKms {
    #[napi(constructor)]
    pub fn new(storage: &AskarStorage) -> Self {
        let storage = storage.clone();
        let kms = askar::kms::AskarKms::new(storage.0.clone());

        InternalAskarKms(kms)
    }

    #[napi]
    pub async fn create(&self, kt: KeyType) -> Result<String> {
        self.0
            .create(kt.into(), Default::default())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn get(&self, kid: String) -> Result<InternalAskarKeyHandle> {
        self.0
            .get(&kid)
            .await
            .map(InternalAskarKeyHandle)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn get_by_public_key(&self, public_key: Vec<u8>) -> Result<InternalAskarKeyHandle> {
        self.0
            .get_by_public_key(public_key.as_slice())
            .await
            .map(InternalAskarKeyHandle)
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
pub struct InternalAskarKeyHandle(askar::kms::AskarKeyHandle);

#[napi]
impl InternalAskarKeyHandle {
    #[napi(getter)]
    pub fn pub_key(&self) -> Result<Vec<u8>> {
        self.0
            .pub_key()
            .map(Into::into)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi(getter)]
    pub fn jwk(&self) -> Option<String> {
        self.0
            .jwk()
            .and_then(|value| serde_json::to_string(&value).ok())
    }

    #[napi(getter)]
    pub fn alg(&self) -> Result<Alg> {
        self.0.alg().try_into()
    }

    #[napi]
    pub async fn sign(&self, payload: &[u8]) -> Result<Uint8Array> {
        self.0
            .sign(payload)
            .await
            .map(Into::into)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[napi]
    pub async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.0
            .verify(data, signature)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

#[napi]
pub enum KeyType {
    Ed25519,
    P256,
    K256,
}

#[napi]
pub enum Alg {
    ES256,
    ES256K,
    EdDSA,
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

impl From<Alg> for askar::kms::Alg {
    fn from(value: Alg) -> Self {
        match value {
            Alg::ES256 => askar::kms::Alg::ES256,
            Alg::ES256K => askar::kms::Alg::ES256K,
            Alg::EdDSA => askar::kms::Alg::EdDSA,
        }
    }
}

impl From<KeyType> for askar::kms::KeyType {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::P256 => askar::kms::KeyType::P256,
            KeyType::K256 => askar::kms::KeyType::K256,
            KeyType::Ed25519 => askar::kms::KeyType::Ed25519,
        }
    }
}
