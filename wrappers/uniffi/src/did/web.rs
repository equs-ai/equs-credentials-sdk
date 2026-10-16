use crate::did::VerificationMethodKey;
use crate::http::{HttpClient, WrappedHttpClient};
use equs_sdk::did::VerificationMethodKey as EqusSdkVerificationMethodKey;
use equs_sdk::did::didweb::DIDWeb as EqusSdkDIDWeb;
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
pub struct DIDWeb(EqusSdkDIDWeb);

#[uniffi::export]
impl DIDWeb {
    #[uniffi::constructor]
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        let wrapped_client = Arc::new(WrappedHttpClient::new(http_client));
        Self(EqusSdkDIDWeb::new(wrapped_client))
    }
    pub fn generate_did_from_url(&self, url: String) -> Result<String> {
        EqusSdkDIDWeb::generate_did_from_url(&url).map_err(|e| DIDWebError::Generate(e.to_string()))
    }

    pub fn generate_did_document(
        &self,
        did: String,
        keys: Vec<Arc<VerificationMethodKey>>,
    ) -> Result<String> {
        let mut vmk = vec![];

        for key in keys.iter() {
            vmk.push(EqusSdkVerificationMethodKey {
                verification_relationships: key.verification_relationships.to_owned(),
                key: &key.key,
            });
        }

        EqusSdkDIDWeb::generate_did_document(&did, &vmk)
            .map_err(|e| DIDWebError::Generate(e.to_string()))
            .map(|d| serde_json::to_string(&d).map_err(|e| DIDWebError::Document(e.to_string())))?
    }
}
