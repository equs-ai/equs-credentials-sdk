use crate::vc::Alg;
use agent_sdk::crypto::{Key, Signer, Verifier, JWK};
use agent_sdk::inmem::kms::KeyHandle as ASDKInMemKeyHandle;

type Result<T> = std::result::Result<T, InMemKeyHandleError>;

#[derive(uniffi::Error, Debug)]
pub enum InMemKeyHandleError {
    PubKey(String),
    Sign(String),
    Verify(String),
    Jwk(String),
}
impl std::fmt::Display for InMemKeyHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InMemKeyHandleError::PubKey(s) => {
                write!(f, "InMem KeyHandle pub key error: {s}")
            }
            InMemKeyHandleError::Sign(s) => {
                write!(f, "InMem KeyHandle sign error: {s}")
            }
            InMemKeyHandleError::Verify(s) => {
                write!(f, "InMem KeyHandle verify error: {s}")
            }
            InMemKeyHandleError::Jwk(s) => {
                write!(f, "InMem KeyHandle jwk error: {s}")
            }
        }
    }
}

#[derive(uniffi::Object, Clone)]
pub struct InMemKeyHandle {
    inner: ASDKInMemKeyHandle,
}

impl InMemKeyHandle {
    pub fn new(kh: ASDKInMemKeyHandle) -> Self {
        Self { inner: kh }
    }
    pub fn inner(&self) -> &dyn Key {
        &self.inner
    }
}

impl Key for InMemKeyHandle {
    fn pub_key(&self) -> agent_sdk::crypto::Result<Vec<u8>> {
        self.inner.pub_key()
    }

    fn jwk(&self) -> Option<JWK> {
        self.inner.jwk()
    }
}

#[uniffi::export()]
impl InMemKeyHandle {
    fn alg(&self) -> Alg {
        self.inner.alg()
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .sign(payload)
            .await
            .map(Into::into)
            .map_err(|err| InMemKeyHandleError::Sign(err.to_string()))
    }

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.inner
            .verify(data, signature)
            .await
            .map_err(|err| InMemKeyHandleError::Verify(err.to_string()))
    }
}
