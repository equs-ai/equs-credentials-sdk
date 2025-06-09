use crate::did::VerificationMethodKey;
use agent_sdk::did::didweb::DIDWeb as ASDKDIDWeb;
use agent_sdk::did::VerificationMethodKey as ASDKVerificationMethodKey;
use std::sync::Arc;

#[derive(uniffi::Error, Debug)]
pub enum DIDWebError {
    Generate(String),
    Document(String),
}
impl std::fmt::Display for DIDWebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DIDWebError::Generate(s) => write!(f, "DID web generation error: {s}"),
            DIDWebError::Document(s) => write!(f, "DID web document error: {s}"),
        }
    }
}
type Result<T> = std::result::Result<T, DIDWebError>;

#[derive(uniffi::Object)]
pub struct DIDWeb(ASDKDIDWeb);

#[uniffi::export]
impl DIDWeb {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(ASDKDIDWeb {})
    }
    pub fn generate_did_from_url(&self, url: String) -> Result<String> {
        ASDKDIDWeb::generate_did_from_url(&url).map_err(|e| DIDWebError::Generate(e.to_string()))
    }

    pub fn generate_did_document(
        &self,
        did: String,
        keys: Vec<Arc<VerificationMethodKey>>,
    ) -> Result<String> {
        let mut vmk = vec![];

        for key in keys.iter() {
            vmk.push(ASDKVerificationMethodKey {
                verification_relationships: key.verification_relationships.to_owned(),
                key: &key.key,
            });
        }

        ASDKDIDWeb::generate_did_document(&did, &vmk)
            .map_err(|e| DIDWebError::Generate(e.to_string()))
            .map(|d| serde_json::to_string(&d).map_err(|e| DIDWebError::Document(e.to_string())))?
    }
}
