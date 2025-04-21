use crate::inmem::keyhandle::InMemKeyHandle;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::kms::{CreateOptions, KeyType, Kms};

type Result<T> = std::result::Result<T, InMemKmsError>;

#[derive(uniffi::Error, Debug)]
pub enum InMemKmsError {
    Create(String),
    Get(String),
}
impl std::fmt::Display for InMemKmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InMemKmsError::Create(s) => write!(f, "InMem Kms create error: {s}"),
            InMemKmsError::Get(s) => write!(f, "InMem Kms get error: {s}"),
        }
    }
}

#[uniffi::remote(Enum)]
#[non_exhaustive]
pub enum KeyType {
    Ed25519,
    P256,
    K256,
    Bls12381,
}

#[derive(uniffi::Object)]
pub struct InMemKms(LocalKms);

#[uniffi::export()]
impl InMemKms {
    #[uniffi::constructor]
    pub fn new() -> Self {
        InMemKms(LocalKms::new())
    }

    pub async fn create(&self, kt: KeyType) -> Result<String> {
        self.0
            .create(kt, CreateOptions::default())
            .await
            .map_err(|e| InMemKmsError::Get(e.to_string()))
    }

    pub async fn get(&self, kid: String) -> Result<InMemKeyHandle> {
        self.0
            .get(&kid)
            .await
            .map(InMemKeyHandle::new)
            .map_err(|e| InMemKmsError::Get(e.to_string()))
    }
}

impl InMemKms {
    pub fn inner(&self) -> LocalKms {
        self.0.clone()
    }
}
