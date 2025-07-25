use crate::common::{Error, Result};
use crate::crypto::KeyMetadata;
#[cfg(debug_assertions)]
use crate::inmem::kms::InMemKms;
use crate::vc::{Credential, CredentialMetadata};
#[cfg(debug_assertions)]
use agent_sdk::did::didkey::DIDKey;
#[cfg(debug_assertions)]
use agent_sdk::did::universal::UniversalResolver;
#[cfg(debug_assertions)]
use agent_sdk::did::{DIDBuf, DIDResolver};
#[cfg(debug_assertions)]
use agent_sdk::kms::{CreateOptions, KeyType, Kms};
use agent_sdk::vc::HasClaims;
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::oid4vp::Url;
use serde_json::Value;
use std::collections::HashMap;
#[cfg(debug_assertions)]
use std::str::FromStr;
use uniffi::deps::anyhow;

#[uniffi::export]
pub async fn resolve_metadata(
    credential: Credential,
    metadata: KeyMetadata,
) -> Result<CredentialMetadata> {
    DefaultMetadataProcessor::resolve_metadata(&credential, metadata)
        .map_err(|err| Error::OID4VCIInternal(format!("{:?}", err)))
}

pub fn parse_url_arg(url: &str) -> anyhow::Result<Url> {
    url.parse().map_err(anyhow::Error::from)
}

#[cfg(debug_assertions)]
#[derive(uniffi::Record)]
pub struct DidAndKeyMetadata {
    pub did: String,
    pub key_metadata: KeyMetadata,
}

#[cfg(debug_assertions)]
#[uniffi::export]
pub async fn create_did_and_key_metadata(kms: &InMemKms) -> DidAndKeyMetadata {
    let kms = kms.inner();

    let (kid, key_handle) = kms
        .create_and_handle(KeyType::P256, CreateOptions::default())
        .await
        .unwrap();

    let did = DIDKey::generate(key_handle).unwrap();

    let did_url = UniversalResolver::default()
        .resolve(DIDBuf::from_str(&did).unwrap().as_did())
        .await
        .unwrap()
        .document
        .verification_method
        .first()
        .unwrap()
        .id
        .to_string();

    DidAndKeyMetadata {
        did,
        key_metadata: KeyMetadata { did_url, kid },
    }
}

#[uniffi::export]
pub async fn parse_claims(
    credential: Credential,
) -> std::result::Result<HashMap<String, Value>, Error> {
    let claims = credential
        .parse_claims()
        .map_err(|err| Error::Parse(err.to_string()))?;

    serde_json::from_value(serde_json::to_value(claims).map_err(|e| Error::Parse(e.to_string()))?)
        .map_err(|e| Error::Parse(e.to_string()))
}
