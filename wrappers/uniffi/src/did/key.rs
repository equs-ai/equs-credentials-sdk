use crate::inmem::keyhandle::InMemKeyHandle;
use agent_sdk::did::didkey::DIDKey as ASDKDIDKey;

#[derive(uniffi::Error, Debug)]
pub enum DIDKeyError {
    JWKParseError(String),
    Generate(String),
}
impl std::fmt::Display for DIDKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DIDKeyError::JWKParseError(s) => write!(f, "DID key jwk parse error: {s}"),
            DIDKeyError::Generate(s) => write!(f, "DID key generation error: {s}"),
        }
    }
}
type Result<T> = std::result::Result<T, DIDKeyError>;

#[derive(uniffi::Object)]
pub struct DIDKey(ASDKDIDKey);

#[uniffi::export]
impl DIDKey {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(ASDKDIDKey {})
    }

    pub fn generate(&self, key: &InMemKeyHandle) -> Result<String> {
        ASDKDIDKey::generate(key.to_owned()).map_err(|err| DIDKeyError::Generate(err.to_string()))
    }
}
