use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver};
use agent_sdk::kms::{CreateOptions, KeyType, Kms};
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::oid4vp::Url;
use std::str::FromStr;
use uniffi::deps::anyhow;

use crate::common::{Error, Result};
use crate::crypto::KeyMetadata;
use crate::inmem::kms::InMemKms;
use crate::vc::{Credential, CredentialMetadata};

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
